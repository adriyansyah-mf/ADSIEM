//go:build windows

package task

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Windows isolation uses Windows Defender Firewall: block everything by
// default and allow only the SIEM server, so the agent keeps reporting and
// can be told to unisolate. Rules are named SIEM-* so they can be found and
// removed. Needs Administrator/SYSTEM, which the service runs as.
const (
	isolateAllowOut = "SIEM-Isolate-Allow-Out"
	isolateAllowIn  = "SIEM-Isolate-Allow-In"
)

func netsh(args ...string) error {
	out, err := exec.Command("netsh", append([]string{"advfirewall"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh advfirewall %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isolateHost(serverURL string) error {
	siemIP, err := resolveSIEMIP(serverURL)
	if err != nil {
		return fmt.Errorf("resolve SIEM IP: %w", err)
	}
	_ = netsh("firewall", "delete", "rule", "name="+isolateAllowOut)
	_ = netsh("firewall", "delete", "rule", "name="+isolateAllowIn)
	steps := [][]string{
		{"firewall", "add", "rule", "name=" + isolateAllowOut, "dir=out", "action=allow", "remoteip=" + siemIP},
		{"firewall", "add", "rule", "name=" + isolateAllowIn, "dir=in", "action=allow", "remoteip=" + siemIP},
		{"set", "allprofiles", "state", "on"},
		{"set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
	}
	for _, s := range steps {
		if err := netsh(s...); err != nil {
			_ = unisolateHost() // don't leave the host half-isolated
			return err
		}
	}
	slog.Info("host isolated", "allowed", siemIP)
	return nil
}

// unisolateHost restores Windows' default policy (block inbound, allow
// outbound); a custom pre-isolation policy is not restored.
func unisolateHost() error {
	err := netsh("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
	_ = netsh("firewall", "delete", "rule", "name="+isolateAllowOut)
	_ = netsh("firewall", "delete", "rule", "name="+isolateAllowIn)
	return err
}

func blockIP(ip string, durationSeconds int) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("block_ip: %q is not an IP address", ip)
	}
	name := "SIEM-Block-" + ip
	if err := netsh("firewall", "add", "rule", "name="+name, "dir=in", "action=block", "remoteip="+ip); err != nil {
		return err
	}
	if err := netsh("firewall", "add", "rule", "name="+name, "dir=out", "action=block", "remoteip="+ip); err != nil {
		_ = netsh("firewall", "delete", "rule", "name="+name)
		return err
	}
	// Auto-unblock in-process; a restart before then leaves the rule (named
	// SIEM-Block-<ip>) for an analyst to remove.
	time.AfterFunc(time.Duration(durationSeconds)*time.Second, func() {
		if err := netsh("firewall", "delete", "rule", "name="+name); err != nil {
			slog.Warn("auto-unblock failed", "ip", ip, "err", err)
		}
	})
	slog.Info("blocked IP", "ip", ip, "seconds", durationSeconds)
	return nil
}
