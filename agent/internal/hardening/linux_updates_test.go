package hardening

import "testing"

// checkAutoSecurityUpdates shells out to systemctl — smoke test only, same
// reasoning as checkFirewallActive/checkAuditdActive.
func TestCheckAutoSecurityUpdates_ReturnsValidStatus(t *testing.T) {
	assertValidStatus(t, checkAutoSecurityUpdates(), "upd-auto-security-updates")
}
