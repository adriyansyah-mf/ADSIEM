package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEngineDryRunAppliesNothing(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fw.json")
	eng := New(Options{
		Enabled:   true,
		DryRun:    true,
		ServerURL: "http://172.20.0.4:8000",
		StatePath: state,
	})

	status := eng.Status()
	if status["backend"] != "noop(dry-run)" {
		t.Fatalf("expected dry-run backend, got %v", status["backend"])
	}

	rule, err := eng.Add(Rule{Action: ActionBlock, CIDR: "198.51.100.9", Direction: DirInbound, TTL: 30 * time.Second})
	if err != nil {
		t.Fatalf("dry-run add must succeed, got %v", err)
	}
	if rule.ID == "" {
		t.Fatal("rule id must be set")
	}

	planned, ok := eng.Status()["planned"].([]string)
	if !ok || len(planned) != 1 {
		t.Fatalf("expected one planned command, got %v", eng.Status()["planned"])
	}
	if !strings.Contains(planned[0], "198.51.100.9") || !strings.Contains(planned[0], "timeout 30s") {
		t.Fatalf("planned command missing rule details: %q", planned[0])
	}
	if len(eng.List()) != 1 {
		t.Fatalf("dry-run should still track the rule, got %d", len(eng.List()))
	}
}

func TestEngineRejectsProtectedTargetEvenInDryRun(t *testing.T) {
	eng := New(Options{
		Enabled:   true,
		DryRun:    true,
		ServerURL: "http://172.20.0.4:8000",
		StatePath: filepath.Join(t.TempDir(), "fw.json"),
	})

	if _, err := eng.Add(Rule{Action: ActionBlock, CIDR: "172.20.0.4", Direction: DirInbound}); err == nil {
		t.Fatal("guard must reject the SIEM IP even when dry-running")
	}
	if len(eng.List()) != 0 {
		t.Fatal("rejected rule must not be tracked")
	}
}

func TestEngineDisabledIsNoop(t *testing.T) {
	eng := New(Options{Enabled: false, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	status := eng.Status()
	if status["backend"] != "noop" {
		t.Fatalf("expected noop backend, got %v", status["backend"])
	}
	if status["degraded"] != "disabled in config" {
		t.Fatalf("expected degraded reason, got %v", status["degraded"])
	}
	if _, err := eng.Add(Rule{Action: ActionBlock, CIDR: "198.51.100.9"}); err != nil {
		t.Fatalf("disabled engine must still accept rules as noop, got %v", err)
	}
}

func TestEngineIsolateRefusesWithoutGuard(t *testing.T) {
	eng := New(Options{Enabled: true, DryRun: true, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	res, err := eng.Isolate()
	if err != nil {
		t.Fatalf("isolate should succeed once protected ranges are allow-listed first: %v", err)
	}
	protected, ok := res["protected"].([]string)
	if !ok || len(protected) == 0 {
		t.Fatalf("isolation must always allow-list protected ranges first, got %v", res)
	}
	foundLoopback := false
	for _, c := range protected {
		if c == "127.0.0.0/8" {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Fatalf("loopback must be in the allow list, got %v", protected)
	}
}

func TestEnginePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "fw.json")

	first := New(Options{Enabled: true, DryRun: true, StatePath: state})
	if _, err := first.Add(Rule{Action: ActionBlock, CIDR: "198.51.100.20", Direction: DirInbound}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("state file must be written: %v", err)
	}

	second := New(Options{Enabled: true, DryRun: true, StatePath: state})
	rules := second.List()
	if len(rules) != 1 || rules[0].CIDR != "198.51.100.20" {
		t.Fatalf("persisted rule not restored: %+v", rules)
	}
}

func TestEngineDropsExpiredPersistedRules(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "fw.json")

	stale := `[{"id":"block|198.51.100.30|inbound","action":"block","cidr":"198.51.100.30",
	"proto":"any","direction":"inbound","ttl":1000000000,"reason":"","created_at":"2020-01-01T00:00:00Z",
	"expires_at":"2020-01-01T00:00:01Z"}]`
	if err := os.WriteFile(state, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := New(Options{Enabled: true, DryRun: true, StatePath: state})
	if rules := eng.List(); len(rules) != 0 {
		t.Fatalf("expired rule must not be restored: %+v", rules)
	}
}

func TestEngineRemoveUnknownRule(t *testing.T) {
	eng := New(Options{Enabled: true, DryRun: true, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	if err := eng.Remove("does-not-exist"); err == nil {
		t.Fatal("removing an unknown rule must error")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("SIEM_FW_DRY_RUN", "1")
	eng := New(Options{Enabled: true, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	if eng.Status()["backend"] != "noop(dry-run)" {
		t.Fatalf("SIEM_FW_DRY_RUN must force dry-run, got %v", eng.Status()["backend"])
	}

	t.Setenv("SIEM_FW_DISABLED", "true")
	eng2 := New(Options{Enabled: true, StatePath: filepath.Join(t.TempDir(), "fw.json")})
	if eng2.Status()["enabled"] != false {
		t.Fatalf("SIEM_FW_DISABLED must disable the engine, got %v", eng2.Status()["enabled"])
	}
}
