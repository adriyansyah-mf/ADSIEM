//go:build !linux || linux

package firewall

import (
	"path/filepath"
	"testing"
	"time"
)

func newSyncEngine(t *testing.T) *Engine {
	t.Helper()
	return New(Options{
		Enabled:   true,
		DryRun:    true,
		ServerURL: "http://172.20.0.4:8000",
		StatePath: filepath.Join(t.TempDir(), "fw.json"),
	})
}

func TestSyncAppliesServerRules(t *testing.T) {
	e := newSyncEngine(t)

	added, removed, rejected := e.Sync([]ServerRule{
		{ID: "r1", Action: "block", CIDR: "198.51.100.10", Direction: "both", TTLSeconds: 60, Reason: "manual"},
		{ID: "r2", Action: "block", CIDR: "198.51.100.11", Proto: "tcp", Port: 22, Direction: "inbound"},
	})

	if added != 2 || removed != 0 || len(rejected) != 0 {
		t.Fatalf("added=%d removed=%d rejected=%v", added, removed, rejected)
	}
	if got := len(e.List()); got != 2 {
		t.Fatalf("expected 2 rules, got %d", got)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	e := newSyncEngine(t)
	rules := []ServerRule{{ID: "r1", Action: "block", CIDR: "198.51.100.10", Direction: "both"}}

	e.Sync(rules)
	added, removed, _ := e.Sync(rules)

	if added != 0 || removed != 0 {
		t.Fatalf("re-syncing the same set must be a no-op, added=%d removed=%d", added, removed)
	}
	if got := len(e.List()); got != 1 {
		t.Fatalf("expected 1 rule, got %d", got)
	}
}

func TestSyncRemovesRulesNoLongerOnServer(t *testing.T) {
	e := newSyncEngine(t)

	e.Sync([]ServerRule{
		{ID: "r1", Action: "block", CIDR: "198.51.100.10", Direction: "both"},
		{ID: "r2", Action: "block", CIDR: "198.51.100.11", Direction: "both"},
	})
	added, removed, _ := e.Sync([]ServerRule{
		{ID: "r2", Action: "block", CIDR: "198.51.100.11", Direction: "both"},
	})

	if added != 0 || removed != 1 {
		t.Fatalf("added=%d removed=%d, want 0/1", added, removed)
	}
	if got := e.List(); len(got) != 1 || got[0].ID != "r2" {
		t.Fatalf("wrong survivor: %+v", got)
	}
}

func TestSyncNeverRemovesLocalDetectionRules(t *testing.T) {
	e := newSyncEngine(t)

	if _, err := e.Add(Rule{
		Action:    ActionBlock,
		CIDR:      "198.51.100.99",
		Direction: DirBoth,
		Reason:    "local:ssh_bruteforce",
		TTL:       10 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	_, removed, _ := e.Sync(nil)
	if removed != 0 {
		t.Fatalf("server sync must not remove locally detected blocks, removed=%d", removed)
	}
	if len(e.List()) != 1 {
		t.Fatal("local rule disappeared")
	}
}

func TestSyncRejectsServerRuleTargetingSIEM(t *testing.T) {
	e := newSyncEngine(t)

	added, _, rejected := e.Sync([]ServerRule{
		{ID: "bad", Action: "block", CIDR: "172.20.0.4", Direction: "both"},
		{ID: "good", Action: "block", CIDR: "198.51.100.20", Direction: "both"},
	})

	if added != 1 {
		t.Fatalf("only the safe rule should apply, added=%d", added)
	}
	if len(rejected) != 1 {
		t.Fatalf("the protected rule must be rejected, got %v", rejected)
	}
	for _, r := range e.List() {
		if r.ID == "bad" {
			t.Fatal("a rule blocking the SIEM server must never be applied")
		}
	}
}

func TestSyncRejectsInvalidRule(t *testing.T) {
	e := newSyncEngine(t)
	added, _, rejected := e.Sync([]ServerRule{
		{ID: "bad", Action: "block", CIDR: "not-an-ip"},
	})
	if added != 0 || len(rejected) != 1 {
		t.Fatalf("invalid cidr must be rejected, added=%d rejected=%v", added, rejected)
	}
}

func TestSyncCarriesServerReasonAndTTL(t *testing.T) {
	e := newSyncEngine(t)
	e.Sync([]ServerRule{
		{ID: "r1", Action: "block", CIDR: "198.51.100.10", Direction: "both", TTLSeconds: 300, Reason: "incident-42"},
	})

	rules := e.List()
	if len(rules) != 1 {
		t.Fatal("rule missing")
	}
	if rules[0].TTL != 300*time.Second {
		t.Fatalf("ttl=%v want 300s", rules[0].TTL)
	}
	if rules[0].Reason != "server:incident-42" {
		t.Fatalf("reason=%q must be prefixed to survive local/remote distinction", rules[0].Reason)
	}
}
