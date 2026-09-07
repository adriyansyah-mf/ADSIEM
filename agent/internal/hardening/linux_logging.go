package hardening

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// systemctlCheckTimeout bounds each systemctl probe the same way
// firewallCheckTimeout bounds firewall-backend probes — a hung systemctl
// call must never freeze the synchronous hygiene collector.
const systemctlCheckTimeout = 5 * time.Second

// unitActive reports whether any of the given systemd unit names is active.
// Returns (true, unitName) on the first active match, (false, "") otherwise.
// If systemctl itself isn't present (minimal container, no systemd), every
// call errors and the caller treats that as not_applicable rather than fail.
func unitActive(units ...string) (bool, string, error) {
	for _, u := range units {
		ctx, cancel := context.WithTimeout(context.Background(), systemctlCheckTimeout)
		out, err := exec.CommandContext(ctx, "systemctl", "is-active", u).Output()
		cancel()
		if err != nil {
			continue // this unit isn't installed/active — try the next candidate
		}
		if strings.TrimSpace(string(out)) == "active" {
			return true, u, nil
		}
	}
	// Distinguish "systemctl doesn't exist at all" from "none of the units are active".
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, "", err
	}
	return false, "", nil
}

func checkAuditdActive() Check {
	const id = "log-auditd-active"
	const category = "logging"
	const title = "Linux audit daemon (auditd) is active"

	active, unit, err := unitActive("auditd", "audit")
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "systemctl not available on this host (no systemd)"}
	}
	if active {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: unit + " is active"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "auditd is not active"}
}

func checkTimeSyncActive() Check {
	const id = "log-time-sync-active"
	const category = "logging"
	const title = "A time-synchronization service is active (accurate timestamps for audit logs)"

	active, unit, err := unitActive("chronyd", "chrony", "ntpd", "systemd-timesyncd")
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "systemctl not available on this host (no systemd)"}
	}
	if active {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: unit + " is active"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "no time-sync service (chronyd/ntpd/systemd-timesyncd) is active"}
}
