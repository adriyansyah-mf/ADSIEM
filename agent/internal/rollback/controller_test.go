package rollback

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestControllerSnapshotsAndRestoresOnlyWhenAuto(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "Documents")
	orig := text("quarterly", 3000)
	write(t, filepath.Join(docs, "q.docx"), orig, time.Now().Add(-time.Hour))
	mode := ModeAuto
	var mu sync.Mutex
	var lines []string
	c := &Controller{
		Store: &Store{Dir: filepath.Join(t.TempDir(), "rollback"), Skip: DefaultSkip},
		Push:  func(_, l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() },
		Mode:  func() string { return mode },
		Paths: func() []string { return []string{root, filepath.Join(root, "missing")} },
	}
	c.SnapshotNow()
	c.SnapshotNow() // the second success within a day is not reported
	if len(lines) != 1 || !strings.Contains(lines[0], "event=rollback_snapshot files=1 copied=1") {
		t.Fatalf("lines %v", lines)
	}
	time.Sleep(10 * time.Millisecond)
	since := time.Now()
	write(t, filepath.Join(docs, "q.docx"), random(30000), since.Add(time.Second))

	mode = ModeOff
	c.Restore(42, "/tmp/x", since, []string{docs})
	if got, _ := os.ReadFile(filepath.Join(docs, "q.docx")); bytes.Equal(got, orig) {
		t.Fatal("restored while the policy is off")
	}
	mode = ModeAuto
	c.Restore(42, "/tmp/x", since, []string{docs})
	if got, _ := os.ReadFile(filepath.Join(docs, "q.docx")); !bytes.Equal(got, orig) {
		t.Fatal("not restored")
	}
	if last := lines[len(lines)-1]; !strings.Contains(last, "event=ransomware_rollback pid=42") || !strings.Contains(last, "restored=1") {
		t.Fatalf("restore line %s", last)
	}
}

func TestDefaultSkip(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/a/Documents/node_modules": true, "/home/a/Documents/~$report.docx": true,
		"/home/a/Documents/.git": true, "/home/a/Documents/report.docx": false,
		`C:\Users\a\Desktop\desktop.ini`: true,
	} {
		if DefaultSkip(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}
