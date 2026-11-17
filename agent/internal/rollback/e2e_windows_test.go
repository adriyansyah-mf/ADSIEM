//go:build windows

package rollback

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/linsensor"
	"github.com/siem-platform/agent/internal/ransomguard"
	"github.com/siem-platform/agent/internal/winsensor"
)

// TestRollbackEndToEnd with the ETW sensor: an elevated prompt,
// ROLLBACK_E2E=1 (CI: windows-agent.yml).
func TestRollbackEndToEnd(t *testing.T) {
	if os.Getenv("ROLLBACK_E2E") != "1" {
		t.Skip("set ROLLBACK_E2E=1 in an elevated prompt")
	}
	start := func(g *ransomguard.Guard) (func(), error) {
		s, err := winsensor.StartWith(buffer.New(100000), winsensor.Options{OnFile: func(e winsensor.FileEvent) {
			g.Observe(linsensor.FileEvent{Time: e.Time, PID: e.PID, PPID: e.PPID, Image: e.Image,
				Comm: filepath.Base(e.Image), Action: e.Action, Path: e.Path, From: e.From})
		}})
		if err != nil {
			return nil, err
		}
		return func() { s.Stop() }, nil
	}
	// the guard ends a process with TerminateProcess(h, 1)
	killed := func(err error) bool {
		var ee *exec.ExitError
		return errors.As(err, &ee) && ee.ExitCode() == 1
	}
	runEndToEnd(t, longPath(t, t.TempDir()), start, killed)
}

// longPath: TEMP is in 8.3 form on the runner and ETW reports long paths.
func longPath(t *testing.T, p string) string {
	in, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		t.Fatalf("GetLongPathName(%s): %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}
