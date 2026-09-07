package hardening

import "testing"

func TestCollect_ReturnsAllSixteenChecks(t *testing.T) {
	r := Collect(nil)
	if len(r.Checks) != 16 {
		t.Fatalf("expected 16 checks, got %d", len(r.Checks))
	}
	seen := make(map[string]bool)
	for _, c := range r.Checks {
		if seen[c.ID] {
			t.Fatalf("duplicate check ID: %s", c.ID)
		}
		seen[c.ID] = true
		if c.Category == "" || c.Title == "" {
			t.Fatalf("check %s missing category or title", c.ID)
		}
	}
}
