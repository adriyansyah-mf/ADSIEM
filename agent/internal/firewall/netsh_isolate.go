package firewall

import (
	"fmt"
	"strings"
)

// Windows isolation: the firewall profiles block both directions by default
// (IPv4 and IPv6: the policy is per profile, not per address family), and two
// allow rules keep what isolation must not cut. A block rule can't do this on
// Windows: block rules win over allow rules there, so 0.0.0.0/0 would cut the
// server too. The rule names are the ones the native isolate task uses, so
// either path releases the other's isolation.
const (
	isolateAllowOut = "SIEM-Isolate-Allow-Out"
	isolateAllowIn  = "SIEM-Isolate-Allow-In"
)

// Isolate (and, when already isolated, an allow list update).
func (b *NetshBackend) Isolate(allow []string) error {
	remote := netshRemoteIPs(allow)
	if remote == "" {
		return fmt.Errorf("no address to keep reachable: refusing to isolate")
	}
	b.deleteIsolationRules()
	steps := [][]string{
		{"firewall", "add", "rule", "name=" + isolateAllowOut, "dir=out", "action=allow", "remoteip=" + remote, "enable=yes"},
		{"firewall", "add", "rule", "name=" + isolateAllowIn, "dir=in", "action=allow", "remoteip=" + remote, "enable=yes"},
		{"set", "allprofiles", "state", "on"},
		{"set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
	}
	for _, s := range steps {
		if err := b.netsh(s...); err != nil {
			_ = b.Unisolate() // never leave it half applied
			return err
		}
	}
	return nil
}

// Unisolate restores Windows' default policy (block unsolicited inbound,
// allow outbound) and removes the allow rules.
func (b *NetshBackend) Unisolate() error {
	if err := b.netsh("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"); err != nil {
		return err
	}
	b.deleteIsolationRules()
	return nil
}

func (b *NetshBackend) deleteIsolationRules() {
	for _, n := range []string{isolateAllowOut, isolateAllowIn} {
		_ = b.netsh("firewall", "delete", "rule", "name="+n) // absent: fine
	}
}

// netshRemoteIPs joins addresses for remoteip=, IPv4 and IPv6, dropping
// anything that isn't one.
func netshRemoteIPs(allow []string) string {
	var out []string
	for _, c := range allow {
		if _, n, err := parseTarget(strings.TrimSpace(c)); err == nil {
			out = append(out, n.String())
		}
	}
	return strings.Join(out, ",")
}
