//go:build linux

package procexec

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

// The exec hook (the script scanner's Linux source) gets each program's argv
// as a list, from the real kernel. PROCEXEC_E2E=1, as root.
func TestExecHookGetsArgv(t *testing.T) {
	if os.Getenv("PROCEXEC_E2E") != "1" {
		t.Skip("set PROCEXEC_E2E=1 (needs root and BTF)")
	}
	var mu sync.Mutex
	var seen []Exec
	m, err := StartWith(buffer.New(10000), func(ex Exec) {
		mu.Lock()
		seen = append(seen, ex)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	marker := fmt.Sprintf("hook%d", time.Now().UnixNano())
	if out, err := exec.Command("sh", "-c", "echo "+marker).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		mu.Lock()
		for _, ex := range seen {
			if len(ex.Args) == 3 && ex.Args[0] == "sh" && ex.Args[1] == "-c" && ex.Args[2] == "echo "+marker {
				mu.Unlock()
				if !strings.HasSuffix(ex.Image, "sh") || ex.PID == 0 {
					t.Fatalf("exec %+v", ex)
				}
				return
			}
		}
		mu.Unlock()
	}
	t.Fatalf("no exec with argv [sh -c echo %s]; saw %d execs", marker, len(seen))
}
