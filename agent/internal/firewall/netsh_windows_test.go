//go:build windows

package firewall

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Real Windows Defender Firewall (CI: windows-latest, elevated). Addresses are
// TEST-NET-3, never routed.

func firewallRule(t *testing.T, name string) string {
	t.Helper()
	out, err := execPowerShell(context.Background(), findRulesScript(name,
		"ForEach-Object { $_.Action.ToString() + ' ' + $_.Direction.ToString() + ' ' + (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',') }"))
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return strings.TrimSpace(out)
}

func TestNetshBackendOnWindowsFirewall(t *testing.T) {
	b := NewNetsh()
	if !b.Available() {
		t.Fatal("netsh backend not available on an elevated Windows host")
	}
	if err := b.Ensure(); err != nil {
		t.Fatal(err)
	}
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.250/32", Direction: DirBoth}.normalize()
	t.Cleanup(func() { _ = b.Remove(r) })
	if err := b.Apply(r); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]string{"in": "Block Inbound 203.0.113.250", "out": "Block Outbound 203.0.113.250"} {
		if got := firewallRule(t, netshRuleName(r, dir)); !strings.HasPrefix(got, want) {
			t.Fatalf("%s rule: %q, want %q", dir, got, want)
		}
	}
	listed, err := b.List()
	if err != nil || len(listed) == 0 {
		t.Fatalf("list %v %v", listed, err)
	}
	if err := b.Remove(r); err != nil {
		t.Fatal(err)
	}
	if got := firewallRule(t, netshRuleName(r, "in")); got != "" {
		t.Fatalf("rule still present after remove: %q", got)
	}
}

// A TTL block disappears from Windows Firewall: Windows has no expiry, the
// engine's sweep removes it.
func TestEngineExpiresBlocksOnWindows(t *testing.T) {
	e := New(Options{Enabled: true, Backend: "auto"})
	if !e.Enforcing() || e.Status()["backend"] != "netsh" {
		t.Fatalf("engine not enforcing with netsh: %v", e.Status())
	}
	if err := e.BlockFromDetection("test", "203.0.113.251", 1); err != nil {
		t.Fatal(err)
	}
	r := Rule{Action: ActionBlock, CIDR: "203.0.113.251", Direction: DirBoth}.normalize() // as BlockFromDetection builds it
	t.Cleanup(func() { _ = e.backend.Remove(r) })
	if got := firewallRule(t, netshRuleName(r, "in")); !strings.HasPrefix(got, "Block Inbound") {
		t.Fatalf("detection block not applied: %q (status %v)", got, e.Status())
	}
	if n := e.Sweep(time.Now().Add(2 * time.Second)); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if got := firewallRule(t, netshRuleName(r, "in")); got != "" {
		t.Fatalf("expired block still in Windows Firewall: %q", got)
	}
}
