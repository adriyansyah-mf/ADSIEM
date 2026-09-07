package sca

import "testing"

func TestLoadPoliciesEmbeddedDefault(t *testing.T) {
	policies, err := LoadPolicies()
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 embedded policy, got %d", len(policies))
	}
	p := policies[0]
	if p.ID != "cis_linux" {
		t.Fatalf("expected id cis_linux, got %q", p.ID)
	}
	if len(p.Checks) != 21 {
		t.Fatalf("expected 21 checks, got %d", len(p.Checks))
	}

	seen := make(map[string]bool)
	for _, c := range p.Checks {
		if seen[c.ID] {
			t.Fatalf("duplicate check ID: %s", c.ID)
		}
		seen[c.ID] = true
		if c.Category == "" || c.Title == "" {
			t.Fatalf("check %s missing category or title", c.ID)
		}
		if c.Special == "" && len(c.Rules) == 0 {
			t.Fatalf("check %s has neither rules nor a special evaluator", c.ID)
		}
		// Every declared rule must parse — a policy authoring error should
		// surface at test time, not at StatusError on a live host.
		for _, raw := range c.Rules {
			if _, err := parseRule(raw); err != nil {
				t.Fatalf("check %s: %v", c.ID, err)
			}
		}
	}
}

func TestEvaluateReturnsValidShape(t *testing.T) {
	policies, err := LoadPolicies()
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	results := Evaluate(policies, nil)
	if len(results) != 21 {
		t.Fatalf("expected 21 results, got %d", len(results))
	}
	for _, r := range results {
		switch r.Status {
		case StatusPass, StatusFail, StatusNotApplicable, StatusError:
		default:
			t.Fatalf("check %s: unexpected status %q", r.ID, r.Status)
		}
		if r.Detail == "" {
			t.Fatalf("check %s: empty detail", r.ID)
		}
	}
}

func TestReplacePolicyOverridesByID(t *testing.T) {
	base := []Policy{{ID: "a", Name: "old"}}
	replaced := replacePolicy(base, Policy{ID: "a", Name: "new"})
	if len(replaced) != 1 || replaced[0].Name != "new" {
		t.Fatalf("expected override in place, got %+v", replaced)
	}
	appended := replacePolicy(base, Policy{ID: "b", Name: "extra"})
	if len(appended) != 2 {
		t.Fatalf("expected append for a new ID, got %+v", appended)
	}
}
