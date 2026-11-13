package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// IOCSetter is a backend that can hold the IP IoC blocklist
// (internal/ipblock) as one set, replaced whole on every change: per-rule
// Apply would spawn one process per address, and a list has thousands.
type IOCSetter interface {
	SetIOCs(v4, v6 []string) error
}

// ErrIOCUnsupported: the backend in force (noop, disabled, degraded) cannot drop IoCs.
var ErrIOCUnsupported = errors.New("firewall backend cannot enforce the IP IoC blocklist")

// IOCResult is what SetIOCs enforced.
type IOCResult struct {
	Applied  int      // CIDRs handed to the backend
	Rejected []string // "cidr: why", refused by the guard or unparseable
	Backend  string
}

// SetIOCs replaces the IoC blocklist with cidrs (addresses or CIDRs, IPv4 or
// IPv6); nil or empty clears it. The anti-lockout guard drops entries that
// cover the SIEM server, the gateway or a protected network, so a poisoned
// list cannot cut the agent off. Traffic both to and from an IoC is dropped,
// established connections included.
func (e *Engine) SetIOCs(cidrs []string) (IOCResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := IOCResult{Backend: e.backend.Name()}
	setter, ok := e.backend.(IOCSetter)
	if !ok {
		return res, ErrIOCUnsupported
	}
	v4, v6 := make([]string, 0, len(cidrs)), []string{}
	seen := make(map[netip.Prefix]bool, len(cidrs))
	for _, raw := range cidrs {
		p, err := parseIOC(raw)
		if err != nil {
			res.Rejected = append(res.Rejected, fmt.Sprintf("%s: %v", raw, err))
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		if err := e.guard.Protect(Rule{Action: ActionBlock, CIDR: p.String()}); err != nil {
			res.Rejected = append(res.Rejected, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	if err := setter.SetIOCs(v4, v6); err != nil {
		e.emit("ioc_set_failed", Rule{Reason: "ipblock"}, err.Error())
		return res, err
	}
	res.Applied = len(v4) + len(v6)
	detail := ""
	if len(res.Rejected) > 0 {
		detail = fmt.Sprintf("%d rejected: %s", len(res.Rejected), strings.Join(firstN(res.Rejected, 5), "; "))
	}
	e.emit("ioc_set_applied", Rule{Reason: fmt.Sprintf("ipblock: %d entries", res.Applied)}, detail)
	return res, nil
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// parseIOC accepts an address or a CIDR and returns the masked prefix; an
// IPv4-mapped IPv6 address becomes IPv4.
func parseIOC(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ── nftables ────────────────────────────────────────────────────────────────

// iocTable is its own table, hooked before siem_fw (priority -10) and without
// an established-connection accept, so a newly listed address loses the
// connections it already has.
const iocTable = "siem_ioc"

// SetIOCs rebuilds the siem_ioc table in one nft transaction: the table is
// created (so delete never fails), deleted and recreated with its sets.
func (b *NftBackend) SetIOCs(v4, v6 []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*nftTimeoutMs)
	defer cancel()
	return b.script(ctx, nftIOCScript(v4, v6))
}

func nftIOCScript(v4, v6 []string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "add table inet %s\ndelete table inet %s\n", iocTable, iocTable)
	if len(v4) == 0 && len(v6) == 0 {
		return s.String()
	}
	fmt.Fprintf(&s, "table inet %s {\n", iocTable)
	fmt.Fprintf(&s, "  set v4 { type ipv4_addr ; flags interval ; auto-merge ;%s }\n", nftElements(v4))
	fmt.Fprintf(&s, "  set v6 { type ipv6_addr ; flags interval ; auto-merge ;%s }\n", nftElements(v6))
	s.WriteString("  chain input { type filter hook input priority -10 ; policy accept ;\n")
	s.WriteString("    ip saddr @v4 drop\n    ip6 saddr @v6 drop\n  }\n")
	s.WriteString("  chain output { type filter hook output priority -10 ; policy accept ;\n")
	s.WriteString("    ip daddr @v4 drop\n    ip6 daddr @v6 drop\n  }\n")
	s.WriteString("  chain forward { type filter hook forward priority -10 ; policy accept ;\n")
	s.WriteString("    ip saddr @v4 drop\n    ip daddr @v4 drop\n    ip6 saddr @v6 drop\n    ip6 daddr @v6 drop\n  }\n")
	s.WriteString("}\n")
	return s.String()
}

func nftElements(cidrs []string) string {
	if len(cidrs) == 0 {
		return ""
	}
	return " elements = { " + strings.Join(cidrs, ", ") + " } ;"
}

// ── netsh (fallback when WFP is unavailable) ────────────────────────────────

const (
	netshIOCIn    = "SIEM-IOC-in"
	netshIOCOut   = "SIEM-IOC-out"
	netshIOCChunk = 200 // addresses per rule: netsh's remoteip list is bounded
)

// SetIOCs replaces the SIEM-IOC-in/-out rules: every rule of those names is
// deleted, then one rule per chunk of addresses is added per direction.
func (b *NetshBackend) SetIOCs(v4, v6 []string) error {
	for _, name := range []string{netshIOCIn, netshIOCOut} {
		// "No rules match" is the expected result when there are none; a real
		// failure shows up when the add below finds the rules still there.
		_ = b.netsh("firewall", "delete", "rule", "name="+name)
	}
	all := append(append([]string{}, v4...), v6...)
	for start := 0; start < len(all); start += netshIOCChunk {
		end := min(start+netshIOCChunk, len(all))
		list := "remoteip=" + strings.Join(all[start:end], ",")
		for _, d := range []struct{ name, dir string }{{netshIOCIn, "in"}, {netshIOCOut, "out"}} {
			if err := b.netsh("firewall", "add", "rule", "name="+d.name, "dir="+d.dir,
				"action=block", "enable=yes", "profile=any", list); err != nil {
				return fmt.Errorf("netsh ioc rule: %w", err)
			}
		}
	}
	return nil
}

// ── noop: dry-run records what it would enforce ─────────────────────────────

// SetIOCs on the noop backend only records the set in dry-run mode, so
// `firewall_list` and tests can see it; a disabled or degraded firewall
// enforces nothing and says so.
func (n *NoopBackend) SetIOCs(v4, v6 []string) error {
	if !n.DryRun {
		return ErrIOCUnsupported
	}
	n.ops = append(n.ops, plannedOp{Op: "ioc", Argv: [][]string{{"-f", "-", nftIOCScript(v4, v6)}}})
	return nil
}
