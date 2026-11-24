//go:build windows

package task

import (
	"errors"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/firewall"
)

// Isolation on Windows always uses Windows Defender Firewall directly (it
// blocks both directions, stronger than the engine's inbound-only isolate);
// block_ip uses the engine (netsh backend) when it enforces, else netsh here
// (isolation_windows.go). Rules are parsed with the same firewall.ParseRule.
const nativeFirewall = true

func nativeIsolate(serverURL string) error { return isolateHost(serverURL) }

func nativeUnisolate() error { return unisolateHost() }

// nativeIsolated reports whether nativeIsolate's allow rule is in place:
// netsh exits non-zero when no rule matches. ok is false when netsh could not
// run at all.
func nativeIsolated() (isolated, ok bool) {
	err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+isolateAllowOut).Run()
	if err == nil {
		return true, true
	}
	var exit *exec.ExitError
	return false, errors.As(err, &exit)
}

func blockRuleName(cidr string) string {
	return "SIEM-Block-" + strings.NewReplacer("/", "_", ":", "-").Replace(cidr)
}

func nativeBlock(rule firewall.Rule) error {
	name := blockRuleName(rule.CIDR)
	_ = netsh("firewall", "delete", "rule", "name="+name) // idempotent re-block
	for _, dir := range []string{"in", "out"} {
		if err := netsh("firewall", "add", "rule", "name="+name, "dir="+dir, "action=block",
			"remoteip="+rule.CIDR); err != nil {
			_ = netsh("firewall", "delete", "rule", "name="+name)
			return err
		}
	}
	if rule.TTL > 0 {
		// in-process expiry; a restart before then leaves the SIEM-Block-* rule for an analyst
		time.AfterFunc(rule.TTL, func() {
			if err := netsh("firewall", "delete", "rule", "name="+name); err != nil {
				slog.Warn("auto-unblock failed", "cidr", rule.CIDR, "err", err)
			}
		})
	}
	return nil
}

func nativeUnblock(rule firewall.Rule) error {
	return netsh("firewall", "delete", "rule", "name="+blockRuleName(rule.CIDR))
}
