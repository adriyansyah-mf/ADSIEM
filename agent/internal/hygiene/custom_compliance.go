package hygiene

import (
	"sync"

	"github.com/siem-platform/agent/internal/hardening"
	"github.com/siem-platform/agent/internal/heartbeat"
	"github.com/siem-platform/agent/internal/sca"
)

// customRules holds the latest analyst-authored SCA rules delivered via the
// heartbeat response (see heartbeat.HeartbeatResponse.CustomComplianceRules).
// Guarded by a mutex the same way tailer.Manager/fim.Watcher guard their own
// live-updated state — set from cmd/agent/main.go's heartbeat onConfig
// callback, read by collectCustomCompliance on each hygiene cycle.
var (
	customRulesMu sync.RWMutex
	customRules   []heartbeat.CustomComplianceRule
)

// SetCustomComplianceRules replaces the current set of agent-evaluated
// custom compliance rules.
func SetCustomComplianceRules(rules []heartbeat.CustomComplianceRule) {
	customRulesMu.Lock()
	defer customRulesMu.Unlock()
	customRules = rules
}

func getCustomComplianceRules() []heartbeat.CustomComplianceRule {
	customRulesMu.RLock()
	defer customRulesMu.RUnlock()
	return customRules
}

// collectCustomCompliance evaluates every current custom rule and appends
// its result to r.HardeningChecks with an ID prefixed "custom-<control-id>"
// — the server's hygiene-ingest route recognizes that prefix and syncs the
// result back into the owning custom_compliance_controls row (see
// server-api/app/api/routes/hygiene.py). Panic-guarded the same way
// collectHardening is: a bug in one analyst-authored rule must never take
// down the rest of the hygiene report.
func collectCustomCompliance(r *Report) {
	defer func() {
		recover()
	}()
	rules := getCustomComplianceRules()
	if len(rules) == 0 {
		return
	}

	policy := sca.Policy{ID: "custom"}
	for _, cr := range rules {
		policy.Checks = append(policy.Checks, sca.PolicyCheck{
			ID:        "custom-" + cr.ID,
			Category:  "custom",
			Title:     "Custom compliance control",
			Condition: cr.Condition,
			Rules:     cr.Rules,
		})
	}

	for _, res := range sca.Evaluate([]sca.Policy{policy}, nil) {
		r.HardeningChecks = append(r.HardeningChecks, hardening.Check{
			ID: res.ID, Category: res.Category, Title: res.Title,
			Status: hardening.Status(res.Status), Detail: res.Detail,
		})
	}
}
