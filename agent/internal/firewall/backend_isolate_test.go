package firewall

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestNetshIsolateBlocksBothDirectionsAndAllowsTheList(t *testing.T) {
	f := newFakeWindows()
	b := f.backend()
	if err := b.Isolate([]string{"192.0.2.10/32", "::1/128", "bogus"}); err != nil {
		t.Fatal(err)
	}
	var policy, allowOut, allowIn bool
	for _, c := range f.calls {
		line := strings.Join(c, " ")
		switch {
		case strings.Contains(line, "firewallpolicy blockinbound,blockoutbound"):
			policy = true
		case strings.Contains(line, "name="+isolateAllowOut) && strings.Contains(line, "add"):
			allowOut = strings.Contains(line, "dir=out") && strings.Contains(line, "remoteip=192.0.2.10/32,::1/128")
		case strings.Contains(line, "name="+isolateAllowIn) && strings.Contains(line, "add"):
			allowIn = strings.Contains(line, "dir=in") && strings.Contains(line, "remoteip=192.0.2.10/32,::1/128")
		}
	}
	if !policy || !allowOut || !allowIn {
		t.Fatalf("policy=%v out=%v in=%v calls=%v", policy, allowOut, allowIn, f.calls)
	}

	if err := b.Unisolate(); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-3]
	if strings.Join(last, " ") != "advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound" {
		t.Fatalf("unisolate must restore the default policy first, got %v", last)
	}
	if f.rules[isolateAllowIn] || f.rules[isolateAllowOut] {
		t.Fatal("allow rules must be removed")
	}
}

func TestNetshIsolateFailureRollsBack(t *testing.T) {
	f := newFakeWindows()
	f.fail = "blockinbound,blockoutbound"
	if err := f.backend().Isolate([]string{"192.0.2.10/32"}); err == nil {
		t.Fatal("expected failure")
	}
	if f.rules[isolateAllowIn] || f.rules[isolateAllowOut] {
		t.Fatal("a failed isolation must not leave its allow rules behind")
	}
}

func TestNetshIsolateRefusesAnEmptyAllowList(t *testing.T) {
	f := newFakeWindows()
	if err := f.backend().Isolate([]string{"not-an-ip"}); err == nil {
		t.Fatal("nothing to keep reachable: must refuse")
	}
	if len(f.calls) != 0 {
		t.Fatalf("no netsh call expected, got %v", f.calls)
	}
}

func TestNftIsolateIsOneTransaction(t *testing.T) {
	var scripts []string
	b := NewNftWithRunner(func(_ context.Context, argv ...string) (string, error) {
		if len(argv) == 3 && argv[0] == "-f" && argv[1] == "-" {
			scripts = append(scripts, argv[2])
		}
		return "", nil
	})
	if err := b.Isolate([]string{"192.0.2.10/32", "fd00::2", "127.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 {
		t.Fatalf("one nft -f script expected, got %d", len(scripts))
	}
	s := scripts[0]
	for _, want := range []string{
		"delete table inet siem_isolate",
		"type ipv4_addr; flags interval;",
		"elements = { 192.0.2.10/32, 127.0.0.0/8 }",
		"elements = { fd00::2/128 }",
		"hook input priority -10; policy drop;",
		"hook output priority -10; policy drop;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "established") {
		t.Error("isolation must not accept established connections: an open C2 session would survive")
	}
}

func TestSplitFamilies(t *testing.T) {
	v4, v6 := splitFamilies([]string{"10.0.0.1", "10.0.0.0/8", "::1", "fe80::/10", "junk"})
	if !slices.Equal(v4, []string{"10.0.0.1/32", "10.0.0.0/8"}) || !slices.Equal(v6, []string{"::1/128", "fe80::/10"}) {
		t.Fatalf("v4=%v v6=%v", v4, v6)
	}
}
