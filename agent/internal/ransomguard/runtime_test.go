package ransomguard

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// The group policy (SetRuntime): report only, excluded programs, isolate
// asked by the policy, and off.
func TestRuntimeFromGroupPolicy(t *testing.T) {
	dir := t.TempDir()
	var out sink
	isolated := 0
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, CanaryNames: []string{".c.pdf"}, Kill: true,
		IsolateFunc: func() error { isolated++; return nil }})
	var killed []uint32
	g.response = func(pid uint32) (int, error) { killed = append(killed, pid); return 1, nil }
	g.can.plant()
	hit := func(pid uint32, image string) {
		g.Observe(linsensor.FileEvent{Action: "write", Path: filepath.Join(dir, ".c.pdf"), PID: pid, Image: image,
			Comm: filepath.Base(image)})
	}

	g.SetRuntime(Runtime{Kill: false}) // report
	hit(100, "/tmp/locker")
	if l := out.wait(t, 1)[0]; !strings.Contains(l, "response=none") || len(killed) != 0 {
		t.Fatalf("report only: %s killed=%v", l, killed)
	}

	g.SetRuntime(Runtime{Kill: true, Isolate: true, Excluded: func(img string) bool { return img == "/usr/bin/restic" }})
	g.can.plant()
	hit(200, "/usr/bin/restic")
	if l := out.wait(t, 2)[1]; !strings.Contains(l, "response=none") || len(killed) != 0 {
		t.Fatalf("excluded program: reported, not stopped: %s", l)
	}
	g.can.plant()
	hit(300, "/tmp/locker")
	if l := out.wait(t, 3)[2]; !strings.Contains(l, "response=killed") || killed[0] != 300 || isolated != 1 {
		t.Fatalf("stop + isolate from the policy: %s killed=%v isolated=%d", l, killed, isolated)
	}

	count := func() int {
		time.Sleep(100 * time.Millisecond)
		out.mu.Lock()
		defer out.mu.Unlock()
		return len(out.lines)
	}
	before := count() // a third strike also retires the canary: one more line
	g.SetRuntime(Runtime{Off: true})
	g.can.plant()
	hit(400, "/tmp/locker")
	if after := count(); after != before {
		t.Fatalf("off: nothing reported (%d lines, was %d)", after, before)
	}
}
