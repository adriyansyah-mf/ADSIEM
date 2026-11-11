package task

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/firewall"
)

func newEngine(t *testing.T, enabled, dryRun bool) *firewall.Engine {
	t.Helper()
	return firewall.New(firewall.Options{
		Enabled:   enabled,
		DryRun:    dryRun,
		Backend:   "noop",
		StatePath: filepath.Join(t.TempDir(), "firewall.json"),
		ServerURL: "http://127.0.0.1:8000",
	})
}

// A block on the no-op backend used to report success while nothing was
// enforced (SOAR showed "IP blocked" for 114 blocks that never happened).
func TestRequireEnforcingFailsOnDisabledFirewall(t *testing.T) {
	err := requireEnforcing(newEngine(t, false, false))
	if err == nil {
		t.Fatal("disabled firewall must fail the block, not report success")
	}
	if !strings.Contains(err.Error(), "disabled in config") || !strings.Contains(err.Error(), "firewall.enabled: true") {
		t.Fatalf("error should say why and how to fix it: %v", err)
	}
}

func TestRequireEnforcingAllowsDryRun(t *testing.T) {
	if err := requireEnforcing(newEngine(t, true, true)); err != nil {
		t.Fatalf("dry-run is the operator's choice and must still succeed: %v", err)
	}
}
