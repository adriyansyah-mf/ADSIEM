package hardening

func checkAutoSecurityUpdates() Check {
	const id = "upd-auto-security-updates"
	const category = "updates"
	const title = "Automatic security updates are enabled"

	active, unit, err := unitActive("unattended-upgrades", "dnf-automatic.timer", "dnf-automatic-install.timer")
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "systemctl not available on this host (no systemd)"}
	}
	if active {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: unit + " is active"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "no automatic-update service (unattended-upgrades/dnf-automatic) is active"}
}
