//go:build linux

package rollback

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/siem-platform/agent/internal/linsensor"
	"github.com/siem-platform/agent/internal/ransomguard"
)

// TestRollbackEndToEnd with the eBPF sensor: root, BTF and tracefs,
// ROLLBACK_E2E=1 (CI).
func TestRollbackEndToEnd(t *testing.T) {
	if os.Getenv("ROLLBACK_E2E") != "1" {
		t.Skip("set ROLLBACK_E2E=1 (needs root, BTF and tracefs)")
	}
	start := func(g *ransomguard.Guard) (func(), error) {
		s, err := linsensor.Start(linsensor.Options{Push: func(string, string) {}, OnFile: g.Observe})
		if err != nil {
			return nil, err
		}
		return func() { s.Stop() }, nil
	}
	killed := func(err error) bool {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return false
		}
		ws, ok := ee.Sys().(syscall.WaitStatus)
		return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
	}
	runEndToEnd(t, t.TempDir(), start, killed)
}
