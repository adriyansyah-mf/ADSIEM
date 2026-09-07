package hardening

import "testing"

func assertValidStatus(t *testing.T, c Check, wantID string) {
	t.Helper()
	switch c.Status {
	case StatusPass, StatusFail, StatusNotApplicable, StatusError:
	default:
		t.Fatalf("unexpected status: %q", c.Status)
	}
	if c.ID != wantID {
		t.Fatalf("unexpected ID: %q", c.ID)
	}
}

// checkAuditdActive/checkTimeSyncActive shell out to systemctl, so — same as
// checkFirewallActive — these are smoke tests (valid shape), not
// deterministic pass/fail tests. Mocking exec.Command would need
// infrastructure this repo doesn't have.
func TestCheckAuditdActive_ReturnsValidStatus(t *testing.T) {
	assertValidStatus(t, checkAuditdActive(), "log-auditd-active")
}

func TestCheckTimeSyncActive_ReturnsValidStatus(t *testing.T) {
	assertValidStatus(t, checkTimeSyncActive(), "log-time-sync-active")
}
