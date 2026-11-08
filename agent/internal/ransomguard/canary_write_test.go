package ransomguard

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

type writeCase struct {
	g      *Guard
	out    *sink
	p      string
	mu     sync.Mutex
	killed []uint32
}

func newWriteCase(t *testing.T) *writeCase {
	t.Helper()
	dir := t.TempDir()
	w := &writeCase{out: &sink{}, p: filepath.Join(dir, ".c.docx")}
	w.g = New(Options{Push: w.out.push, CanaryDirs: []string{dir}, CanaryNames: []string{".c.docx"}, Kill: true})
	w.g.writeWait = 300 * time.Millisecond
	w.g.response = func(pid uint32) (int, error) {
		w.mu.Lock()
		w.killed = append(w.killed, pid)
		w.mu.Unlock()
		return 1, nil
	}
	w.g.can.plant()
	return w
}

func (w *writeCase) write(image string) {
	w.g.Observe(linsensor.FileEvent{Action: "write", Path: w.p, PID: 90, Image: image, Comm: filepath.Base(image)})
}

// quiet waits out the read-back and requires no report and no kill.
func (w *writeCase) quiet(t *testing.T, what string) {
	t.Helper()
	time.Sleep(w.g.writeWait + 200*time.Millisecond)
	w.out.mu.Lock()
	defer w.out.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.out.lines) != 0 || len(w.killed) != 0 {
		t.Fatalf("%s: lines %q killed %v", what, w.out.lines, w.killed)
	}
}

// A write event that leaves the canary as it was (an open for write, a
// sync client putting back the same bytes) is not a hit.
func TestCanaryWriteUnchangedIsNoHit(t *testing.T) {
	w := newWriteCase(t)
	data, _ := os.ReadFile(w.p)
	os.WriteFile(w.p, data, 0o644)
	w.write(`C:\Tools\any.exe`)
	w.quiet(t, "identical content")
	if !w.g.can.isCanary(w.p) {
		t.Fatal("canary forgotten")
	}
}

// OneDrive (Known Folder Move) syncs another device's canary over this one:
// still canary text, so it is adopted, with no report now or at the check.
func TestCanaryWriteByOneDriveStillCanaryIsAdopted(t *testing.T) {
	for _, img := range []string{
		`C:\Program Files\Microsoft OneDrive\OneDrive.exe`,
		`C:\Program Files\Microsoft OneDrive\25.1\OneDrive.Sync.Service.exe`,
		`C:\Program Files\Microsoft OneDrive\25.1\FileCoAuth.exe`,
	} {
		w := newWriteCase(t)
		os.WriteFile(w.p, canaryContent(), 0o644)
		w.write(img)
		w.quiet(t, img)
		w.g.checkCanaries()
		w.quiet(t, img+": periodic check")
	}
}

// Another program writing canary text: not a hit either, but not adopted:
// the periodic check reports the change, unconfirmed, as before.
func TestCanaryWriteOtherProgramStillCanaryNotAdopted(t *testing.T) {
	w := newWriteCase(t)
	os.WriteFile(w.p, canaryContent(), 0o644)
	w.write(`C:\Tools\copier.exe`)
	w.quiet(t, "canary text by another program")
	w.g.checkCanaries()
	if l := w.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary_changed confirmed=false") {
		t.Fatalf("line = %s", l)
	}
}

// A canary destroyed with only a trusted sync client as writer (OneDrive
// syncing down a copy encrypted on another device): confirmed, the sync
// client reported as trusted and not killed, and a detection without a
// process (isolate when asked).
func TestCanaryWriteByOneDriveEncryptedIsConfirmedNotKilled(t *testing.T) {
	w := newWriteCase(t)
	encryptFile(t, w.p)
	w.write(`C:\Program Files\Microsoft OneDrive\OneDrive.exe`)
	lines := w.out.wait(t, 2)
	if !has(lines, "detection=canary confirmed=true response=trusted", "PID=90 ") ||
		!has(lines, "detection=canary_changed confirmed=true") || len(w.kills()) != 0 {
		t.Fatalf("lines = %q killed %v", lines, w.kills())
	}
}

// Canary text gone (overwritten with something else, low entropy): a hit.
// On Linux the event is the open, before the data: the guard reads the
// canary back until it changes or writeWait passes.
func TestCanaryWriteReadBackAfterTheEvent(t *testing.T) {
	w := newWriteCase(t)
	w.write("/tmp/.x/crypt")
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(w.p, []byte("encrypted"), 0o644)
	l := w.out.wait(t, 1)[0]
	if !strings.HasPrefix(l, "detection=canary confirmed=true response=killed") || !strings.Contains(l, "FileAction=write") {
		t.Fatalf("line = %s", l)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.killed) != 1 || w.killed[0] != 90 {
		t.Fatalf("killed %v", w.killed)
	}
}

// Many write events for one canary (Linux reports every open) make one hit.
func TestCanaryWriteBurstIsOneHit(t *testing.T) {
	w := newWriteCase(t)
	encryptFile(t, w.p)
	for i := 0; i < 20; i++ {
		w.write("/tmp/.x/crypt")
	}
	w.out.wait(t, 1)
	time.Sleep(w.g.writeWait)
	w.out.mu.Lock()
	defer w.out.mu.Unlock()
	if len(w.out.lines) != 1 {
		t.Fatalf("lines = %q", w.out.lines)
	}
}
