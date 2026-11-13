package firewall

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetIOCsFiltersThroughTheGuardAndSplitsFamilies(t *testing.T) {
	eng := New(Options{Enabled: true, DryRun: true, ServerURL: "https://172.20.0.4",
		ProtectedIPs: []string{"198.51.100.0/24"}, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	res, err := eng.SetIOCs([]string{
		"45.33.32.156", "45.33.32.156/32", // duplicate once normalised
		"2606:4700:4700::1111", "::ffff:8.8.4.4", // IPv6, IPv4-mapped
		"172.20.0.0/16",  // contains the SIEM server
		"198.51.100.7",   // inside a protected network
		"not-an-address", // unparseable
		"45.33.32.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 4 || len(res.Rejected) != 3 {
		t.Fatalf("applied %d rejected %v", res.Applied, res.Rejected)
	}
	planned := strings.Join(eng.backend.(*NoopBackend).PlannedCommands(), "\n")
	for _, want := range []string{"45.33.32.0/24, 45.33.32.156/32, 8.8.4.4/32", "2606:4700:4700::1111/128",
		"priority -10", "ip daddr @v4 drop", "ip6 saddr @v6 drop"} {
		if !strings.Contains(planned, want) {
			t.Fatalf("planned script lacks %q:\n%s", want, planned)
		}
	}
	if strings.Contains(planned, "172.20.") || strings.Contains(planned, "198.51.100.7") {
		t.Fatalf("guarded addresses reached the backend:\n%s", planned)
	}
}

func TestSetIOCsOnADisabledFirewallIsUnsupported(t *testing.T) {
	eng := New(Options{Enabled: false, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	if _, err := eng.SetIOCs([]string{"45.33.32.156"}); !errors.Is(err, ErrIOCUnsupported) {
		t.Fatalf("want ErrIOCUnsupported, got %v", err)
	}
}

func TestNftIOCScriptRecreatesTheTableAtomically(t *testing.T) {
	var scripts []string
	b := NewNftWithRunner(func(_ context.Context, argv ...string) (string, error) {
		scripts = append(scripts, argv[len(argv)-1])
		return "", nil
	})
	if err := b.SetIOCs([]string{"45.33.32.156/32"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.SetIOCs(nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 2 {
		t.Fatalf("one nft transaction per call, got %d", len(scripts))
	}
	first := scripts[0]
	if !strings.HasPrefix(first, "add table inet siem_ioc\ndelete table inet siem_ioc\ntable inet siem_ioc {") ||
		!strings.Contains(first, "elements = { 45.33.32.156/32 }") || strings.Contains(first, "established") {
		t.Fatalf("unexpected script:\n%s", first)
	}
	// clearing the list leaves no table (no empty chains hooked into the stack)
	if scripts[1] != "add table inet siem_ioc\ndelete table inet siem_ioc\n" {
		t.Fatalf("clear script: %q", scripts[1])
	}
}

func TestNetshIOCRulesAreChunkedAndReplaced(t *testing.T) {
	f := newFakeWindows()
	b := f.backend()
	var list []string
	for i := 0; i < netshIOCChunk+5; i++ {
		list = append(list, fmt.Sprintf("45.33.%d.%d/32", i/250, i%250+1))
	}
	if err := b.SetIOCs(list, []string{"2606:4700:4700::1111/128"}); err != nil {
		t.Fatal(err)
	}
	adds := 0
	for _, c := range f.calls {
		if c[2] == "add" {
			adds++
			remote := c[len(c)-1]
			if n := strings.Count(remote, ",") + 1; n > netshIOCChunk {
				t.Fatalf("rule with %d addresses", n)
			}
		}
	}
	if adds != 4 { // two chunks, in and out
		t.Fatalf("want 4 rules, got %d: %v", adds, f.calls)
	}
	f.calls = nil
	if err := b.SetIOCs(nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0][2] != "delete" || f.calls[1][2] != "delete" || len(f.rules) != 0 {
		t.Fatalf("clearing must only delete: %v rules %v", f.calls, f.rules)
	}
}

func TestParseIOC(t *testing.T) {
	for in, want := range map[string]string{
		"45.33.32.156":       "45.33.32.156/32",
		"45.33.32.156/24":    "45.33.32.0/24",
		"::ffff:8.8.4.4":     "8.8.4.4/32",
		"::ffff:8.8.4.0/120": "8.8.4.0/24",
		" 2606:4700::1 ":     "2606:4700::1/128",
	} {
		p, err := parseIOC(in)
		if err != nil || p.String() != want {
			t.Fatalf("parseIOC(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
}
