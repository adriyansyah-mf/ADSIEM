// Rule DSL grammar (one rule per line in a policy's `rules:` list):
//
//	f:<path>                              file/dir exists
//	not f:<path>                          file/dir does not exist
//	f:<path> -> r:<regex>                 file exists and regex matches a line
//	f:<path> -> !r:<regex>                file exists and regex matches no line
//	f:<path> -> n:<regex> compare <= 90   numeric compare on a captured group
//	f:<path> -> n:<regex> compare between 1..90
//	f:<path> -> perm<=0640                permission bits at most 0640
//	c:<command args...> -> r:<regex>      run command, regex matches stdout+stderr
//	c:<command args...> -> !r:<regex>
//	m:<mountpoint> -> opts:noexec,nosuid  mountpoint carries all listed options
//	sshd:<directive> -> r:<regex> [default:<value>]
//	sshd:<directive> -> n:<regex> compare <= 4 [default:6]
//
// A missing file/command/mount evaluates to "skip" (see rules.go), which
// condition.go excludes from voting — a check whose rules all skip reports
// not_applicable, never a fabricated pass or fail. compare ops: <= >= < > == != between.
package sca

import (
	"embed"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed policies/*.yml
var embeddedPolicies embed.FS

// ExtraPolicyDir is where an operator can drop additional or overriding
// policy YAML files without rebuilding the agent — the entire point of
// moving checks out of compiled Go. A missing directory is not an error;
// most hosts will only ever run the embedded default policy.
const ExtraPolicyDir = "/etc/siem-agent/sca"

// LoadPolicies returns the embedded default policy plus anything found
// under ExtraPolicyDir, in that order. A policy ID collision keeps the
// later (operator-supplied) definition — see loadYAMLPolicies.
func LoadPolicies() ([]Policy, error) {
	var policies []Policy

	entries, err := embeddedPolicies.ReadDir("policies")
	if err != nil {
		return nil, errf("reading embedded policies: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		data, err := embeddedPolicies.ReadFile(filepath.Join("policies", e.Name()))
		if err != nil {
			return nil, errf("reading embedded policy %s: %w", e.Name(), err)
		}
		p, err := parsePolicy(data)
		if err != nil {
			return nil, errf("parsing embedded policy %s: %w", e.Name(), err)
		}
		policies = append(policies, p)
	}

	if extra, err := os.ReadDir(ExtraPolicyDir); err == nil {
		for _, e := range extra {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(ExtraPolicyDir, e.Name()))
			if err != nil {
				continue // unreadable drop-in file — skip it, don't fail the whole agent
			}
			p, err := parsePolicy(data)
			if err != nil {
				continue // malformed drop-in file — same
			}
			policies = replacePolicy(policies, p)
		}
	}

	return policies, nil
}

func parsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// replacePolicy appends p, or overwrites the existing entry with the same
// ID — an operator-supplied policy file overrides the embedded default of
// the same ID rather than running both.
func replacePolicy(policies []Policy, p Policy) []Policy {
	for i, existing := range policies {
		if existing.ID == p.ID {
			policies[i] = p
			return policies
		}
	}
	return append(policies, p)
}

// Evaluate runs every check in every given policy against the live host and
// returns one CheckResult per check, in policy-then-declaration order.
// openPorts is the hygiene collector's already-gathered port list, needed
// only by the no_legacy_services special check (see special.go).
func Evaluate(policies []Policy, openPorts []PortInfo) []CheckResult {
	var results []CheckResult
	for _, policy := range policies {
		for _, check := range policy.Checks {
			results = append(results, evaluateCheck(check, openPorts))
		}
	}
	return results
}

func evaluateCheck(check PolicyCheck, openPorts []PortInfo) CheckResult {
	if check.Special != "" {
		status, detail := evalSpecial(check.Special, openPorts)
		return CheckResult{ID: check.ID, Category: check.Category, Title: check.Title, Status: status, Detail: detail}
	}

	evals := make([]ruleEval, 0, len(check.Rules))
	for _, raw := range check.Rules {
		parsed, err := parseRule(raw)
		if err != nil {
			// A malformed rule in a policy file is an authoring bug, not a
			// host condition — surface it as StatusError on this one check
			// rather than crashing the whole evaluation pass.
			return CheckResult{ID: check.ID, Category: check.Category, Title: check.Title, Status: StatusError, Detail: err.Error()}
		}
		evals = append(evals, parsed.evaluate())
	}
	status, detail := fold(check.Condition, evals)
	return CheckResult{ID: check.ID, Category: check.Category, Title: check.Title, Status: status, Detail: detail}
}
