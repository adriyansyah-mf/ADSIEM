package firewall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWindows records netsh calls and answers rule enumeration from the rules
// it was told to add (no Windows needed).
type fakeWindows struct {
	mu    sync.Mutex
	rules map[string]bool
	calls [][]string
	fail  string // a netsh argument that makes the call fail
}

func newFakeWindows(existing ...string) *fakeWindows {
	f := &fakeWindows{rules: map[string]bool{}}
	for _, n := range existing {
		f.rules[n] = true
	}
	return f
}

func (f *fakeWindows) netsh(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	for _, a := range args {
		if f.fail != "" && a == f.fail {
			return "", errors.New("netsh: exit status 1")
		}
	}
	if len(args) > 4 && args[1] == "firewall" {
		name := strings.TrimPrefix(args[4], "name=")
		switch args[2] {
		case "add":
			f.rules[name] = true
		case "delete":
			if !f.rules[name] {
				return "No rules match the specified criteria.", errors.New("exit status 1")
			}
			delete(f.rules, name)
		}
	}
	return "Ok.", nil
}

func (f *fakeWindows) ps(context.Context, ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for n := range f.rules {
		names = append(names, n)
	}
	return strings.Join(names, "\r\n"), nil
}

func (f *fakeWindows) backend() *NetshBackend { return NewNetshWithRunners(f.netsh, f.ps) }

func TestNetshApplyArgvPerDirectionAndPort(t *testing.T) {
	both := Rule{ID: "block|203.0.113.9/32|both", Action: ActionBlock, CIDR: "203.0.113.9/32", Direction: DirBoth, Proto: "any"}
	got := netshApplyArgv(both)
	want := [][]string{
		{"firewall", "add", "rule", "name=SIEM-FW-block_203.0.113.9_32_both-in", "dir=in", "action=block", "remoteip=203.0.113.9/32", "enable=yes"},
		{"firewall", "add", "rule", "name=SIEM-FW-block_203.0.113.9_32_both-out", "dir=out", "action=block", "remoteip=203.0.113.9/32", "enable=yes"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv\n got %v\nwant %v", got, want)
	}
	svcIn := Rule{ID: "r1", Action: ActionBlock, CIDR: "198.51.100.0/24", Direction: DirInbound, Proto: "tcp", Port: 3389}
	if got := netshApplyArgv(svcIn); len(got) != 1 || got[0][len(got[0])-2] != "protocol=tcp" || got[0][len(got[0])-1] != "localport=3389" {
		t.Fatalf("inbound service rule %v", got)
	}
	svcOut := Rule{ID: "r2", Action: ActionAllow, CIDR: "10.0.0.5/32", Direction: DirOutbound, Proto: "udp", Port: 53}
	if got := netshApplyArgv(svcOut); len(got) != 1 || got[0][5] != "action=allow" || got[0][len(got[0])-1] != "remoteport=53" {
		t.Fatalf("outbound service rule %v", got)
	}
}

func TestNetshApplyRemoveAndStaleCleanup(t *testing.T) {
	f := newFakeWindows("SIEM-FW-old-in", "Other-Product-Rule")
	b := f.backend()
	if err := b.Ensure(); err != nil {
		t.Fatal(err)
	}
	if f.rules["SIEM-FW-old-in"] || !f.rules["Other-Product-Rule"] {
		t.Fatalf("Ensure must remove only SIEM-FW-* rules: %v", f.rules)
	}
	r := Rule{ID: "x", Action: ActionBlock, CIDR: "203.0.113.9/32", Direction: DirBoth, Proto: "any"}
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
	if !f.rules["SIEM-FW-x-in"] || !f.rules["SIEM-FW-x-out"] {
		t.Fatalf("applied %v", f.rules)
	}
	if err := b.Apply(r); err != nil { // re-apply replaces, no duplicate
		t.Fatal(err)
	}
	if err := b.Remove(r); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 1 {
		t.Fatalf("left %v", f.rules)
	}
	if err := b.Remove(r); err != nil { // already gone: not an error
		t.Fatalf("removing an absent rule: %v", err)
	}
}

// A real delete failure (access denied, translated message) is reported,
// not mistaken for "no such rule".
func TestNetshRemoveReportsRealFailures(t *testing.T) {
	f := newFakeWindows("SIEM-FW-x-in", "SIEM-FW-x-out")
	f.fail = "delete"
	err := f.backend().Remove(Rule{ID: "x"})
	if err == nil {
		t.Fatal("a failed delete was reported as success")
	}
}

func TestNetshApplyNeverLeavesOneDirection(t *testing.T) {
	f := newFakeWindows()
	f.fail = "dir=out"
	if err := f.backend().Apply(Rule{ID: "x", CIDR: "203.0.113.9/32", Direction: DirBoth, Action: ActionBlock}); err == nil {
		t.Fatal("expected the outbound half to fail")
	}
	if len(f.rules) != 0 {
		t.Fatalf("half a rule left: %v", f.rules)
	}
}

// Windows rules do not expire: the engine sweeps them, and forgets expired
// ones on every backend so they stop counting against the detection cap.
func TestEngineSweepRemovesExpiredRules(t *testing.T) {
	f := newFakeWindows()
	e := &Engine{backend: f.backend(), guard: NewGuard("", nil), applied: map[string]Rule{}}
	now := time.Now().UTC()
	for _, r := range []Rule{
		{CIDR: "203.0.113.1/32", TTL: time.Minute, CreatedAt: now.Add(-2 * time.Minute)}, // expired
		{CIDR: "203.0.113.2/32", TTL: time.Hour, CreatedAt: now},                         // live
		{CIDR: "203.0.113.3/32"}, // no TTL
	} {
		if _, err := e.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.Sweep(now); n != 1 || e.BlockedEntries() != 2 {
		t.Fatalf("swept %d, %d left", n, e.BlockedEntries())
	}
	for name := range f.rules {
		if strings.Contains(name, "203.0.113.1") {
			t.Fatalf("expired rule still in the firewall: %s", name)
		}
	}
	if n := e.Sweep(now.Add(2 * time.Hour)); n != 1 || e.BlockedEntries() != 1 {
		t.Fatalf("second sweep %d, %d left", n, e.BlockedEntries())
	}
}

func TestExplicitBackendNames(t *testing.T) {
	if got := selectBackend("netsh").Name(); got != "netsh" {
		t.Fatalf("netsh: %s", got)
	}
	if got := selectBackend("nft").Name(); got != "nft" {
		t.Fatalf("nft: %s", got)
	}
}
