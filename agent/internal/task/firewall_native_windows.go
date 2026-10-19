//go:build windows

package task

import (
	"log/slog"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/firewall"
)

// The firewall engine's backend is nftables, which Windows doesn't have (it
// would degrade to noop and silently not isolate), so on Windows the
// isolate/block tasks use Windows Defender Firewall via netsh
// (isolation_windows.go). Rules are parsed with the same firewall.ParseRule.
const nativeFirewall = true

func nativeIsolate(serverURL string) error { return isolateHost(serverURL) }

func nativeUnisolate() error { return unisolateHost() }

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
