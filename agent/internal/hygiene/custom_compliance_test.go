package hygiene

import (
	"testing"

	"github.com/siem-platform/agent/internal/heartbeat"
)

func TestCollectCustomCompliance(t *testing.T) {
	SetCustomComplianceRules([]heartbeat.CustomComplianceRule{
		{ID: "abc123", Rules: []string{"f:/etc/hostname"}, Condition: "all"},
	})
	defer SetCustomComplianceRules(nil)

	r := &Report{}
	collectCustomCompliance(r)

	if len(r.HardeningChecks) != 1 {
		t.Fatalf("expected 1 custom check, got %d", len(r.HardeningChecks))
	}
	c := r.HardeningChecks[0]
	if c.ID != "custom-abc123" {
		t.Fatalf("expected ID custom-abc123, got %q", c.ID)
	}
	if c.Status != "pass" {
		t.Fatalf("expected pass (/etc/hostname exists), got %s (%s)", c.Status, c.Detail)
	}
}

func TestCollectCustomComplianceNoRulesIsNoop(t *testing.T) {
	SetCustomComplianceRules(nil)
	r := &Report{}
	collectCustomCompliance(r)
	if len(r.HardeningChecks) != 0 {
		t.Fatalf("expected no checks when no custom rules configured, got %d", len(r.HardeningChecks))
	}
}
