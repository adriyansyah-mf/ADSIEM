package ransomguard

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

var t0 = time.Unix(1000, 0)

func ev(pid uint32, action, path, from string, at time.Duration) linsensor.FileEvent {
	return linsensor.FileEvent{Time: t0.Add(at), Action: action, Path: path, From: from, PID: pid, Image: "/tmp/x", Comm: "x"}
}

func TestExtensionChange(t *testing.T) {
	d := newDetector(nil)
	var f *finding
	for i := 0; i < minExtRenames; i++ {
		old := fmt.Sprintf("/data/d%d/report%d.%s", i%4, i, []string{"docx", "pdf", "xlsx"}[i%3])
		if got := d.observe(ev(7, "rename", old+".locked", old, time.Duration(i)*time.Second)); got != nil {
			f = got
		}
	}
	if f == nil || f.kind != "extension_change" || f.ext != ".locked" || f.files != minExtRenames {
		t.Fatalf("finding = %+v", f)
	}
	if d.observe(ev(7, "rename", "/a.b.locked", "/a.b", 30*time.Second)) != nil {
		t.Fatal("a process fires once per window")
	}
}

func TestRenamesWithoutCommonExtensionDoNotFire(t *testing.T) {
	d := newDetector(nil)
	for i := 0; i < 3*minExtRenames; i++ {
		if f := d.observe(ev(8, "rename", fmt.Sprintf("/d/f%d.%d", i, i), fmt.Sprintf("/d/f%d.tmp", i), 0)); f != nil {
			t.Fatalf("renames to all different extensions fired: %+v", f)
		}
	}
}

func TestMassModify(t *testing.T) {
	d := newDetector(nil)
	var f *finding
	for i := 0; i < minWrites; i++ {
		p := fmt.Sprintf("/srv/share/dir%d/file%d.dat", i%minWriteDirs, i)
		if got := d.observe(ev(9, "create", p, "", 0)); got != nil {
			f = got
		}
		if i < minDestructive {
			if got := d.observe(ev(9, "delete", p+".orig", "", 0)); got != nil {
				f = got
			}
		}
	}
	if f == nil || f.kind != "mass_modify" {
		t.Fatalf("finding = %+v", f)
	}
	// Many writes alone (a build, an untar) are not enough.
	d2 := newDetector(nil)
	for i := 0; i < 3*minWrites; i++ {
		if got := d2.observe(ev(10, "create", fmt.Sprintf("/b/d%d/o%d.o", i%20, i), "", 0)); got != nil {
			t.Fatalf("writes without deletes fired: %+v", got)
		}
	}
}

func TestAllowlistAndWindow(t *testing.T) {
	d := newDetector([]string{"mybackup"})
	for _, img := range []string{"/usr/bin/rsync", "/opt/mybackup"} {
		for i := 0; i < 2*minExtRenames; i++ {
			e := ev(11, "rename", fmt.Sprintf("/d/%d.bak", i), fmt.Sprintf("/d/%d.txt", i), 0)
			e.Image = img
			if f := d.observe(e); f != nil {
				t.Fatalf("%s is allowed: %+v", img, f)
			}
		}
	}
	// Renames spread over more than a window never add up.
	for i := 0; i < 2*minExtRenames; i++ {
		if f := d.observe(ev(12, "rename", fmt.Sprintf("/d/%d.enc", i), fmt.Sprintf("/d/%d.txt", i), time.Duration(i)*window/10)); f != nil {
			t.Fatalf("slow renames fired: %+v", f)
		}
	}
}

func TestConfirmByEntropy(t *testing.T) {
	dir := t.TempDir()
	random := make([]byte, 8192)
	rand.Read(random)
	enc := []string{}
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("e%d", i))
		os.WriteFile(p, random[i*100:], 0o644)
		enc = append(enc, p)
	}
	plain := filepath.Join(dir, "plain.txt")
	os.WriteFile(plain, []byte(strings.Repeat("quarterly report, nothing to see here. ", 200)), 0o644)
	if ok, e := confirm(enc); !ok || e < encryptedEntropy {
		t.Fatalf("random data not confirmed: %v %.2f", ok, e)
	}
	if ok, _ := confirm([]string{plain, plain, plain}); ok {
		t.Fatal("text confirmed as encrypted")
	}
	if ok, _ := confirm([]string{filepath.Join(dir, "gone")}); ok {
		t.Fatal("nothing readable must not confirm")
	}
}

func TestCanaries(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "alice"), 0o755)
	os.Mkdir(filepath.Join(dir, "bob"), 0o755)
	c := newCanaries([]string{filepath.Join(dir, "*"), filepath.Join(dir, "missing")}, nil)
	if n := c.plant(); n != 4 {
		t.Fatalf("planted %d", n)
	}
	a := filepath.Join(dir, "alice", "!siem-canary.pdf")
	if !c.isCanary(a) || c.isCanary(filepath.Join(dir, "alice", "notes.txt")) {
		t.Fatal("isCanary")
	}
	if bad := c.verify(); len(bad) != 0 {
		t.Fatalf("fresh canaries reported: %v", bad)
	}
	os.WriteFile(a, []byte("encrypted"), 0o644)
	os.Remove(filepath.Join(dir, "bob", ".siem-canary.docx"))
	bad := c.verify()
	if len(bad) != 2 {
		t.Fatalf("verify = %v", bad)
	}
	if n := c.plant(); n != 4 {
		t.Fatalf("replanted %d", n)
	}
	if b, _ := os.ReadFile(a); !strings.Contains(string(b), "ransomware protection") {
		t.Fatal("canary not rewritten")
	}
}

type sink struct {
	mu    sync.Mutex
	lines []string
}

func (s *sink) push(_, l string) {
	s.mu.Lock()
	s.lines = append(s.lines, l)
	s.mu.Unlock()
}

func (s *sink) wait(t *testing.T, n int) []string {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		if len(s.lines) >= n {
			defer s.mu.Unlock()
			return append([]string(nil), s.lines...)
		}
		s.mu.Unlock()
	}
	t.Fatalf("want %d lines, have %q", n, s.lines)
	return nil
}

func TestGuardCanaryKillsAndReports(t *testing.T) {
	dir := t.TempDir()
	var out sink
	var killed []uint32
	var mu sync.Mutex
	isolated := false
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, Kill: true, Isolate: func() error { isolated = true; return nil }})
	g.response = func(pid uint32) (int, error) { mu.Lock(); killed = append(killed, pid); mu.Unlock(); return 3, nil }
	g.can.plant()
	canary := filepath.Join(dir, "!siem-canary.pdf")
	g.Observe(linsensor.FileEvent{Action: "rename", From: canary, Path: canary + ".locked", PID: 42, PPID: 1, UID: 1000, Image: "/tmp/.x/crypt", Comm: "crypt"})
	lines := out.wait(t, 1)
	want := `detection=canary confirmed=true response=killed Canary="` + canary + `" FileAction=rename Image="/tmp/.x/crypt" Comm="crypt" PID=42 PPID=1 User=1000 Killed=3 Isolated=true`
	if lines[0] != want {
		t.Fatalf("got  %s\nwant %s", lines[0], want)
	}
	if len(killed) != 1 || killed[0] != 42 || !isolated {
		t.Fatalf("killed=%v isolated=%t", killed, isolated)
	}
}

func TestGuardUnconfirmedHeuristicOnlyReports(t *testing.T) {
	dir := t.TempDir()
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{filepath.Join(dir, "none")}, Kill: true})
	g.response = func(uint32) (int, error) { t.Error("must not kill without confirmation"); return 0, nil }
	for i := 0; i < minExtRenames; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%d.txt", i))
		os.WriteFile(p+".bak", []byte(strings.Repeat("plain text ", 100)), 0o644)
		g.Observe(linsensor.FileEvent{Time: t0, Action: "rename", From: p, Path: p + ".bak", PID: 5, Image: "/usr/bin/renamer", Comm: "renamer"})
	}
	lines := out.wait(t, 1)
	if !strings.HasPrefix(lines[0], "detection=extension_change confirmed=false response=none Files=20 Extension=\".bak\"") {
		t.Fatalf("line = %s", lines[0])
	}
}

func TestGuardRefusesProtected(t *testing.T) {
	dir := t.TempDir()
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, Kill: true})
	g.response = func(uint32) (int, error) { t.Error("killed a protected process"); return 0, nil }
	g.can.plant()
	g.Observe(linsensor.FileEvent{Action: "write", Path: filepath.Join(dir, ".siem-canary.docx"), PID: 77, Image: "/usr/sbin/sshd", Comm: "sshd"})
	if l := out.wait(t, 1)[0]; !strings.Contains(l, "response=kill_refused") {
		t.Fatalf("line = %s", l)
	}
}
