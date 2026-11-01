package ransomguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

func TestCanariesHiddenByDefault(t *testing.T) {
	dir := t.TempDir()
	c := newCanaries([]string{dir}, nil, false)
	c.plant()
	for p := range c.files {
		if !strings.HasPrefix(filepath.Base(p), ".") {
			t.Errorf("visible canary %s", p)
		}
	}
	v := newCanaries([]string{t.TempDir()}, nil, true)
	v.plant()
	found := false
	for p := range v.files {
		found = found || filepath.Base(p) == "!siem-canary.pdf"
	}
	if !found {
		t.Fatalf("canary_visible should plant !siem-canary.pdf: %v", v.files)
	}
}

func TestLegacyCanaryRemoved(t *testing.T) {
	dir := t.TempDir()
	mine, theirs := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.Mkdir(mine, 0o755)
	os.Mkdir(theirs, 0o755)
	os.WriteFile(filepath.Join(mine, "!siem-canary.pdf"), canaryContent(), 0o644)
	os.WriteFile(filepath.Join(theirs, "!siem-canary.pdf"), []byte("a user's own file"), 0o644)

	newCanaries([]string{filepath.Join(dir, "*")}, nil, false).plant()
	if _, err := os.Stat(filepath.Join(mine, "!siem-canary.pdf")); !os.IsNotExist(err) {
		t.Fatalf("old agent canary left in sight: %v", err)
	}
	if _, err := os.Stat(filepath.Join(theirs, "!siem-canary.pdf")); err != nil {
		t.Fatalf("a file without the canary marker was removed: %v", err)
	}
	// In visible mode the name is current, not legacy.
	os.WriteFile(filepath.Join(mine, "!siem-canary.pdf"), canaryContent(), 0o644)
	if newCanaries([]string{mine}, nil, true).plant(); !exists(filepath.Join(mine, "!siem-canary.pdf")) {
		t.Fatal("visible mode removed its own canary")
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// On Windows the sensor may report a canary in another case than planted.
func TestCanaryPathFoldsCaseOnWindows(t *testing.T) {
	dir := t.TempDir()
	c := newCanaries([]string{dir}, []string{".C.pdf"}, false)
	c.plant()
	planted := filepath.Join(dir, ".C.pdf")
	other := strings.ToUpper(planted)
	c.fold = false
	if c.isCanary(other) {
		t.Fatal("case-sensitive host matched another case")
	}
	c.fold = true
	if p, ok := c.canaryPath(other); !ok || p != planted {
		t.Fatalf("canaryPath(%q) = %q, %v", other, p, ok)
	}
}

func TestGuardKillsOnWindowsCanaryInAnotherCase(t *testing.T) {
	dir := t.TempDir()
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, CanaryNames: []string{".c.pdf"}, Kill: true})
	g.can.fold = true
	var killed uint32
	g.response = func(pid uint32) (int, error) { killed = pid; return 1, nil }
	g.can.plant()
	g.Observe(linsensor.FileEvent{Action: "delete", Path: strings.ToUpper(filepath.Join(dir, ".c.pdf")), PID: 3100,
		Image: `C:\Users\bob\AppData\Local\Temp\LOCKER.EXE`, Comm: "LOCKER.EXE"})
	if l := out.wait(t, 1)[0]; !strings.Contains(l, "detection=canary confirmed=true response=killed") ||
		!strings.Contains(l, `Canary="`+filepath.Join(dir, ".c.pdf")+`"`) || killed != 3100 {
		t.Fatalf("line = %s, killed %d", l, killed)
	}
}

func TestWindowsAllowListIgnoresCase(t *testing.T) {
	d := newDetector(nil)
	for i := 0; i < 2*minExtRenames; i++ {
		e := ev(13, "rename", fmt.Sprintf(`C:\d\%d.bak`, i), fmt.Sprintf(`C:\d\%d.txt`, i), 0)
		e.Image, e.Comm = `C:\Windows\System32\Robocopy.exe`, "Robocopy.exe"
		if f := d.observe(e); f != nil {
			t.Fatalf("robocopy is allowed: %+v", f)
		}
	}
}

func TestCanaryRetiresAndRearms(t *testing.T) {
	dir := t.TempDir()
	now := t0
	c := newCanaries([]string{dir}, []string{".c.pdf"}, false)
	c.now = func() time.Time { return now }
	p := filepath.Join(dir, ".c.pdf")

	// Hits spread over more than the window never retire.
	for i := 0; i < 2*retireAfter; i++ {
		c.plant()
		if c.strike(p) {
			t.Fatalf("hit %d retired across windows", i)
		}
		now = now.Add(retireWindow / 2)
	}
	now = now.Add(retireWindow) // the old hits age out
	for i := 1; i <= retireAfter; i++ {
		c.plant()
		os.Remove(p)
		if got := c.strike(p); got != (i == retireAfter) {
			t.Fatalf("hit %d: retired=%t", i, got)
		}
		now = now.Add(time.Minute)
	}
	if c.plant(); exists(p) || c.isCanary(p) {
		t.Fatal("a retired canary was planted again")
	}
	now = now.Add(retireWindow)
	if c.plant(); !c.isCanary(p) {
		t.Fatal("canary not re-armed after the window")
	}
}

func TestGuardReportsRetired(t *testing.T) {
	dir := t.TempDir()
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, CanaryNames: []string{".c.pdf"}, Kill: true})
	g.response = func(uint32) (int, error) { return 1, nil }
	p := filepath.Join(dir, ".c.pdf")
	for i := 0; i < retireAfter; i++ {
		g.can.plant()
		g.Observe(linsensor.FileEvent{Action: "delete", Path: p, PID: 50, Image: "/usr/bin/deployer", Comm: "deployer"})
		out.wait(t, i+1)
	}
	lines := out.wait(t, retireAfter+1)
	if !strings.HasPrefix(lines[retireAfter], `detection=canary_retired confirmed=false response=none Canary="`+p+`" Image="/usr/bin/deployer"`) {
		t.Fatalf("lines = %q", lines)
	}
	if g.can.plant(); g.can.isCanary(p) {
		t.Fatal("retired canary replanted")
	}
}
