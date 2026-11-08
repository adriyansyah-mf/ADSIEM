package ransomguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/linsensor"
)

// The Windows profile layout in miniature: "All Users" is a junction to
// ProgramData, whose Documents is a junction to Public\Documents. Globbing
// Users\* reached the same directory twice, so two canaries were one file:
// each plant overwrote the other and the periodic check reported both
// changed every 30 s until they retired. Symlinks stand in for junctions.
func TestCanaryDirsSkipLinksAndDuplicates(t *testing.T) {
	root := t.TempDir()
	users := filepath.Join(root, "Users")
	public := filepath.Join(users, "Public", "Documents")
	bob := filepath.Join(users, "bob", "Documents")
	programData := filepath.Join(root, "ProgramData")
	for _, d := range []string{public, bob, programData} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		if err := os.Symlink(target, name); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	link(public, filepath.Join(programData, "Documents")) // ProgramData\Documents -> Public\Documents
	link(programData, filepath.Join(users, "All Users"))  // All Users -> ProgramData
	link(bob, filepath.Join(users, "bobby"))              // a symlinked profile dir
	// Default User is a junction on Windows; a real directory of that name
	// is skipped by name too.
	os.MkdirAll(filepath.Join(users, "Default User", "Documents"), 0o755)
	// A real directory reached through a linked parent: only file identity
	// tells it is the same as Users\bob\Documents.
	os.MkdirAll(filepath.Join(root, "real", "Documents"), 0o755)
	link(filepath.Join(root, "real"), filepath.Join(root, "alias"))

	c := newCanaries([]string{
		filepath.Join(users, "*", "Documents"),
		filepath.Join(root, "real", "Documents"),
		filepath.Join(root, "alias", "Documents"),
	}, []string{".c.pdf"}, false)
	if n := c.plant(); n != 3 {
		t.Fatalf("planted %d canaries, want 3 (Public, bob, real): %v", n, keys(c.files))
	}
	for _, want := range []string{public, bob, filepath.Join(root, "real", "Documents")} {
		if !c.isCanary(filepath.Join(want, ".c.pdf")) {
			t.Errorf("no canary in %s: %v", want, keys(c.files))
		}
	}
	// Nothing changes between checks: no canary rewrites another.
	for i := 0; i < 3; i++ {
		if bad := c.verify(); len(bad) != 0 {
			t.Fatalf("check %d: %v changed with nothing running", i, bad)
		}
		c.plant()
	}
}

// Through the guard: no canary_changed, no retirement, with no ransomware.
func TestGuardNoChangesThroughLinkedDirs(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "Public")
	os.MkdirAll(real, 0o755)
	if err := os.Symlink(real, filepath.Join(root, "All Users")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{filepath.Join(root, "*")}, Kill: true})
	g.can.plant()
	for i := 0; i < 2*retireAfter; i++ {
		g.checkCanaries()
	}
	if len(out.lines) != 0 {
		t.Fatalf("reports with nothing running: %q", out.lines)
	}
}

func keys(m map[string]string) []string {
	var k []string
	for p := range m {
		k = append(k, p)
	}
	return k
}

// Field case: OneDriveSetup.exe (AppData\Local\Microsoft\OneDrive\Update)
// wrote 800 PNG tiles (entropy 7.2x) and deleted the old ones: mass_modify
// was confirmed and the updater killed. It is allowlisted now, and PNGs
// keep their header, so even an unlisted program doing that is not confirmed.
func TestOneDriveSetupPNGTilesNotKilled(t *testing.T) {
	d := newDetector(nil)
	for _, img := range []string{
		`C:\Users\bob\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe`,
		`C:\Users\bob\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe`,
	} {
		for i := 0; i < 4*minWrites; i++ {
			p := fmt.Sprintf(`C:\Users\bob\AppData\Local\Microsoft\OneDrive\25.1\images\d%d\tile%d.png`, i%20, i)
			e := ev(70, "create", p, "", 0)
			e.Image, e.Comm = img, "OneDriveSetup.exe"
			if f := d.observe(e); f != nil {
				t.Fatalf("%s is allowed: %+v", img, f)
			}
			e.Action, e.Path = "delete", p+".old"
			if f := d.observe(e); f != nil {
				t.Fatalf("%s is allowed: %+v", img, f)
			}
		}
	}

	// The same work by a program not on the list: reported, not stopped.
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{filepath.Join(t.TempDir(), "none")}, Kill: true})
	g.response = func(uint32) (int, error) { t.Error("killed an updater writing PNGs"); return 0, nil }
	dir := t.TempDir()
	for i := 0; i < minWrites; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", i%minWriteDirs))
		os.MkdirAll(sub, 0o755)
		p := filepath.Join(sub, fmt.Sprintf("tile%d.png", i))
		writeSample(t, p, headers[".png"])
		g.Observe(linsensor.FileEvent{Time: t0, Action: "create", Path: p, PID: 71, Image: `C:\Tools\TileUpdater.exe`, Comm: "TileUpdater.exe"})
		if i < minDestructive {
			g.Observe(linsensor.FileEvent{Time: t0, Action: "delete", Path: p + ".old", PID: 71, Image: `C:\Tools\TileUpdater.exe`, Comm: "TileUpdater.exe"})
		}
	}
	if l := out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=mass_modify confirmed=false response=none") || !strings.Contains(l, "Entropy=7.") {
		t.Fatalf("line = %s", l)
	}
}
