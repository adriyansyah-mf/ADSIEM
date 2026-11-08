package ransomguard

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// A sync client is trusted from Program Files (admin-only) as it is; from
// the user-writable per-user install only with a valid Microsoft signature.
// Never by its name alone.
func TestSyncClientTrust(t *testing.T) {
	const signedApp = `C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe`
	const signedDesk = `C:\Users\bob\Desktop\OneDrive.exe`
	signed := func(p string) bool { return p == signedApp || p == signedDesk }
	for img, want := range map[string]bool{
		`C:\Program Files\Microsoft OneDrive\OneDrive.exe`:                           true,
		`C:\Program Files (x86)\Microsoft OneDrive\25.1.0\OneDrive.Sync.Service.exe`: true,
		signedApp: true,
		`c:\users\bob\appdata\local\microsoft\onedrive\25.1.0\FileCoAuth.exe`:     false, // unsigned, user-writable
		`C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.Sync.Service.exe`: false, // unsigned
		signedDesk: false, // signed, but not an install location
		`C:\Users\bob\AppData\Local\Temp\Microsoft\OneDrive\OneDrive.exe`:          false,
		`C:\Program Files\Microsoft OneDrive\evil.exe`:                             false,
		`C:\Users\bob\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe`:   false, // the updater is no sync client
		`C:\Program Files\Microsoft OneDrive\..\..\Users\bob\Desktop\OneDrive.exe`: false,
		"/usr/bin/onedrive": false,
	} {
		if got := trustedSync(img, signed); got != want {
			t.Errorf("trustedSync(%s) = %t, want %t", img, got, want)
		}
	}
}

// The review's case: ransomware as the user drops an unsigned OneDrive.exe
// into %LOCALAPPDATA%\Microsoft\OneDrive. A canary delete is a kill, and the
// heuristics see it.
func TestUnsignedOneDriveInUserProfileNotTrusted(t *testing.T) {
	const fake = `C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe`
	w := newWriteCase(t)
	w.g.setSigned(func(string) bool { return false })
	os.Remove(w.p)
	w.g.Observe(linsensor.FileEvent{Action: "delete", Path: w.p, PID: 93, Image: fake, Comm: "OneDrive.exe"})
	if l := w.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary confirmed=true response=killed") {
		t.Fatalf("line = %s", l)
	}
	f := (*finding)(nil)
	for i := 0; i < minExtRenames; i++ {
		e := ev(94, "rename", fmt.Sprintf(`C:\Users\bob\Documents\d%d\r%d.docx.lck`, i%3, i), fmt.Sprintf(`C:\Users\bob\Documents\d%d\r%d.docx`, i%3, i), 0)
		e.Image, e.Comm = fake, "OneDrive.exe"
		if got := w.g.det.observe(e); got != nil {
			f = got
		}
	}
	if f == nil || f.kind != "extension_change" {
		t.Fatalf("heuristics skipped an unsigned OneDrive.exe: %+v", f)
	}
	// Signed and in place: trusted by the heuristics too.
	w.g.setSigned(func(string) bool { return true })
	for i := 0; i < 2*minExtRenames; i++ {
		e := ev(95, "rename", fmt.Sprintf(`C:\Users\bob\Documents\r%d.docx.tmp`, i), fmt.Sprintf(`C:\Users\bob\Documents\r%d.docx`, i), 0)
		e.Image, e.Comm = fake, "OneDrive.exe"
		if got := w.g.det.observe(e); got != nil {
			t.Fatalf("signed OneDrive not trusted: %+v", got)
		}
	}
	// Names alone are trusted nowhere: OneDrive.exe or OneDriveSetup.exe in Temp.
	for _, img := range []string{`C:\Users\bob\AppData\Local\Temp\OneDrive.exe`, `C:\Users\bob\AppData\Local\Temp\OneDriveSetup.exe`} {
		f = nil
		for i := 0; i < minExtRenames; i++ {
			e := ev(96, "rename", fmt.Sprintf(`C:\Users\bob\Documents\x%d.pdf.enc`, i), fmt.Sprintf(`C:\Users\bob\Documents\x%d.pdf`, i), 0)
			e.Image, e.Comm = img, base(img)
			if got := w.g.det.observe(e); got != nil {
				f = got
			}
		}
		if f == nil {
			t.Errorf("%s trusted by name", img)
		}
		w.g.det.procs = map[uint32]*procWindow{}
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
		w.g.setSigned(func(string) bool { return true }) // the per-user install: a Microsoft signature
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
