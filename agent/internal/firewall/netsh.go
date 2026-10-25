package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NetshBackend enforces rules with Windows Defender Firewall. Each rule is
// one firewall rule per direction, named SIEM-FW-<id>-in / -out. Windows
// rules have no expiry, so the engine removes expired ones (ExpiresItself
// false) and Ensure removes SIEM-FW-* rules left by an earlier run, which
// replayState then restores if they are still due.
type NetshBackend struct {
	run runner
	ps  runner // PowerShell: rule enumeration, locale independent (netsh output is translated)
}

const (
	netshPrefix  = "SIEM-FW-"
	netshTimeout = 20 * time.Second
)

func NewNetsh() *NetshBackend { return &NetshBackend{run: execNetsh, ps: execPowerShell} }

// NewNetshWithRunners is for tests.
func NewNetshWithRunners(run, ps runner) *NetshBackend { return &NetshBackend{run: run, ps: ps} }

func (b *NetshBackend) Name() string { return "netsh" }

// ExpiresItself: Windows firewall rules do not time out.
func (b *NetshBackend) ExpiresItself() bool { return false }

func (b *NetshBackend) Available() bool {
	if _, err := exec.LookPath("netsh"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
	defer cancel()
	_, err := b.run(ctx, "advfirewall", "show", "currentprofile")
	return err == nil
}

// Ensure removes every SIEM-FW-* rule: the engine re-applies the ones its
// state still holds, so nothing expired survives a restart.
func (b *NetshBackend) Ensure() error {
	names, err := b.names()
	if err != nil {
		return fmt.Errorf("list SIEM-FW rules: %w", err)
	}
	for _, n := range names {
		if err := b.netsh("firewall", "delete", "rule", "name="+n); err != nil {
			slog.Warn("stale SIEM-FW rule not removed", "rule", n, "err", err)
		}
	}
	return nil
}

func (b *NetshBackend) Apply(rule Rule) error {
	if err := b.Remove(rule); err != nil { // idempotent re-apply
		return fmt.Errorf("apply %s: %w", rule.ID, err)
	}
	for _, argv := range netshApplyArgv(rule) {
		if err := b.netsh(argv...); err != nil {
			_ = b.Remove(rule) // never leave one direction applied
			return fmt.Errorf("apply %s: %w", rule.ID, err)
		}
	}
	return nil
}

// Remove deletes the rule's firewall rules that exist. netsh exits 1 both for
// "no such rule" and for real failures (in a translated message), so present
// rules are found first and every delete error is a real one.
func (b *NetshBackend) Remove(rule Rule) error {
	names, err := b.names()
	if err != nil {
		return fmt.Errorf("remove %s: list: %w", rule.ID, err)
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	var errs []string
	for _, dir := range []string{"in", "out"} {
		name := netshRuleName(rule, dir)
		if !present[name] {
			continue
		}
		if err := b.netsh("firewall", "delete", "rule", "name="+name); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("remove %s: %s", rule.ID, strings.Join(errs, "; "))
	}
	return nil
}

// List returns the rules present, as far as their names say (the engine's
// state is the source of truth for their details).
func (b *NetshBackend) List() ([]Rule, error) {
	names, err := b.names()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Rule
	for _, n := range names {
		id := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(n, netshPrefix), "-in"), "-out")
		if !seen[id] {
			seen[id] = true
			out = append(out, Rule{ID: id})
		}
	}
	return out, nil
}

func (b *NetshBackend) Flush() error { return b.Ensure() }

func (b *NetshBackend) names() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
	defer cancel()
	out, err := b.ps(ctx, findRulesScript(netshPrefix+"*", "Select-Object -ExpandProperty DisplayName"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, netshPrefix) {
			names = append(names, l)
		}
	}
	return names, nil
}

// findRulesScript pipes the firewall rules whose display name matches
// pattern into then. No match is not an error (Get-NetFirewallRule fails
// with ObjectNotFound, even under SilentlyContinue, and its message is
// translated: the category is not); anything else still fails the script.
func findRulesScript(pattern, then string) string {
	return "$ErrorActionPreference = 'Stop'; try { Get-NetFirewallRule -DisplayName '" + pattern + "' | " + then +
		" } catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }"
}

func (b *NetshBackend) netsh(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
	defer cancel()
	_, err := b.run(ctx, append([]string{"advfirewall"}, args...)...)
	return err
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9.-]`)

func netshRuleName(rule Rule, dir string) string {
	return netshPrefix + unsafeName.ReplaceAllString(rule.ID, "_") + "-" + dir
}

// netshApplyArgv is the netsh advfirewall commands for rule, one per
// direction. Inbound matches traffic from the CIDR (to the local port when
// port scoped), outbound traffic to it (to the remote port), as the nft sets.
func netshApplyArgv(rule Rule) [][]string {
	action := "block"
	if rule.Action == ActionAllow {
		action = "allow"
	}
	var dirs []string
	switch rule.Direction {
	case DirInbound:
		dirs = []string{"in"}
	case DirOutbound:
		dirs = []string{"out"}
	default:
		dirs = []string{"in", "out"}
	}
	var out [][]string
	for _, dir := range dirs {
		argv := []string{"firewall", "add", "rule", "name=" + netshRuleName(rule, dir), "dir=" + dir,
			"action=" + action, "remoteip=" + rule.CIDR, "enable=yes"}
		if rule.IsPortScoped() {
			proto := rule.Proto
			if proto == "any" {
				proto = "tcp"
			}
			port := "localport="
			if dir == "out" {
				port = "remoteport="
			}
			argv = append(argv, "protocol="+proto, port+strconv.Itoa(rule.Port))
		}
		out = append(out, argv)
	}
	return out
}

func execNetsh(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "netsh", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("netsh %s: %s: %w", strings.Join(args, " "), text, err)
	}
	return text, nil
}

func execPowerShell(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("powershell: %s: %w", text, err)
	}
	return text, nil
}
