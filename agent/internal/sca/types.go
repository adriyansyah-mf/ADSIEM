// Package sca is a small Security Configuration Assessment engine, modeled
// on Wazuh's SCA module: compliance checks are DATA (YAML policy files with
// a compact rule DSL) evaluated at runtime, not compiled-in Go functions.
// Adding or tuning a check means editing a policy file, not rebuilding and
// redeploying the agent binary.
package sca

// Status mirrors hardening.Status — kept as an independent type so this
// package has no dependency on hardening (hardening depends on sca, not the
// reverse; see hardening/linux.go's adapter).
type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusNotApplicable Status = "not_applicable"
	StatusError         Status = "error"
)

// PortInfo mirrors hardening.PortInfo/hygiene.OpenPort. Duplicated rather
// than imported to keep the dependency direction one-way: hygiene ->
// hardening -> sca, never back up the chain.
type PortInfo struct {
	Port  int
	Proto string
	State string
}

// CheckResult is what Evaluate produces per policy check — the same shape
// hardening.Check has always reported, so the server-side aggregator in
// server-api/app/services/compliance.py needs no changes.
type CheckResult struct {
	ID       string
	Category string
	Title    string
	Status   Status
	Detail   string
}

// Policy is one YAML policy file: a named collection of checks, each
// expressed as a small set of DSL rules (see rules.go) combined by a
// condition (see condition.go).
type Policy struct {
	ID     string        `yaml:"id"`
	Name   string        `yaml:"name"`
	Checks []PolicyCheck `yaml:"checks"`
}

// PolicyCheck is one control. Rules are evaluated and combined per
// Condition ("all" | "any" | "none", default "all"). Special, when set,
// bypasses Rules entirely and dispatches to a hardcoded Go evaluator in
// special.go for logic the DSL can't express cleanly (see package doc in
// special.go for why each of the three exists).
type PolicyCheck struct {
	ID          string              `yaml:"id"`
	Category    string              `yaml:"category"`
	Title       string              `yaml:"title"`
	Description string              `yaml:"description,omitempty"`
	Rationale   string              `yaml:"rationale,omitempty"`
	Remediation string              `yaml:"remediation,omitempty"`
	Compliance  map[string][]string `yaml:"compliance,omitempty"`
	Condition   string              `yaml:"condition,omitempty"` // all | any | none — default all
	Rules       []string            `yaml:"rules,omitempty"`
	Special     string              `yaml:"special,omitempty"`
}
