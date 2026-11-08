package ransomguard

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

func TestSyncClientMatchesInstallPathOnly(t *testing.T) {
	for img, want := range map[string]bool{
		`C:\Program Files\Microsoft OneDrive\OneDrive.exe`:                           true,
		`C:\Program Files (x86)\Microsoft OneDrive\25.1.0\OneDrive.Sync.Service.exe`: true,
		`C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe`:                 true,
		`c:\users\bob\appdata\local\microsoft\onedrive\25.1.0\FileCoAuth.exe`:        true,
		`C:\Users\bob\Desktop\OneDrive.exe`:                                          false, // malware named like it
		`C:\Users\bob\AppData\Local\Temp\Microsoft\OneDrive\OneDrive.exe`:            false,
		`C:\Program Files\Microsoft OneDrive\evil.exe`:                               false,
		`C:\Users\bob\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe`:     false, // the updater is no sync client
		`C:\Program Files\Microsoft OneDrive\..\..\Users\bob\Desktop\OneDrive.exe`:   false,
		"/usr/bin/onedrive": false,
	} {
		if got := syncClient(img); got != want {
			t.Errorf("syncClient(%s) = %t, want %t", img, got, want)
		}
	}
}

// OneDrive (Known Folder Move) renaming or deleting a canary while syncing:
// reported as canary_sync, not killed, not a step toward retirement, and
// the canary is planted again.
func TestCanarySyncRenameDeleteNotKilled(t *testing.T) {
	for _, c := range []struct{ image, action string }{
		{`C:\Program Files\Microsoft OneDrive\OneDrive.exe`, "delete"},
		{`C:\Users\bob\AppData\Local\Microsoft\OneDrive\25.1.0\OneDrive.Sync.Service.exe`, "rename"},
	} {
		w := newWriteCase(t)
		w.g.response = func(uint32) (int, error) { t.Errorf("%s killed", c.image); return 0, nil }
		for i := 0; i < 2*retireAfter; i++ {
			if !w.g.can.isCanary(w.p) {
				t.Fatalf("%s %s: run %d: canary not planted again", c.image, c.action, i)
			}
			ev := linsensor.FileEvent{Action: c.action, Path: w.p, PID: 91, Image: c.image, Comm: base(c.image)}
			if c.action == "rename" {
				ev.From, ev.Path = w.p, w.p+".tmp"
				os.Rename(w.p, ev.Path)
			} else {
				os.Remove(w.p)
			}
			w.g.Observe(ev)
			l := w.out.wait(t, i+1)[i]
			want := "detection=canary_sync confirmed=false response=none Canary=" + kv(w.p) + " FileAction=" + c.action
			if !strings.HasPrefix(l, want) {
				t.Fatalf("%s: got  %s\nwant %s...", c.image, l, want)
			}
			for deadline := time.Now().Add(time.Second); !w.g.can.isCanary(w.p) && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)
			}
		}
		w.g.can.mu.Lock()
		hits := len(w.g.can.hits[w.p])
		w.g.can.mu.Unlock()
		if hits != 0 {
			t.Fatalf("%s: sync changes counted toward retirement (%d)", c.image, hits)
		}
	}
}

// The same file name from anywhere else is not OneDrive: killed as before.
func TestCanaryDeleteByOneDriveNameElsewhereKilled(t *testing.T) {
	w := newWriteCase(t)
	os.Remove(w.p)
	w.g.Observe(linsensor.FileEvent{Action: "delete", Path: w.p, PID: 92, Image: `C:\Users\bob\Desktop\OneDrive.exe`, Comm: "OneDrive.exe"})
	if l := w.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary confirmed=true response=killed") {
		t.Fatalf("line = %s", l)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.killed) != 1 || w.killed[0] != 92 {
		t.Fatalf("killed %v", w.killed)
	}
}

// Canary text written by a binary named OneDrive.exe outside the install
// locations is not adopted: the periodic check reports the change.
func TestCanaryWriteByOneDriveNameElsewhereNotAdopted(t *testing.T) {
	w := newWriteCase(t)
	os.WriteFile(w.p, canaryContent(), 0o644)
	w.write(`C:\Users\bob\Desktop\OneDrive.exe`)
	w.quiet(t, "canary text by a look-alike")
	w.g.checkCanaries()
	if l := w.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary_changed confirmed=false") {
		t.Fatalf("line = %s", l)
	}
}
