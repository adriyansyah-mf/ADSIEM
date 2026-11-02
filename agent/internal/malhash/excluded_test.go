package malhash

import (
	"path/filepath"
	"testing"
)

func TestFileCheckerHonoursExclusions(t *testing.T) {
	st := Open(filepath.Join(t.TempDir(), FileName))
	st.cur.Store(New(ActionBlock, map[string]string{sha("1"): "TestTool"}))
	var lines []string
	quarantined := 0
	fc := &FileChecker{Store: st, Push: func(_, l string) { lines = append(lines, l) },
		Quarantine: func(string) error { quarantined++; return nil },
		Excluded:   func(path, s string) bool { return path == "/opt/lab/sample.bin" }}
	fc.Check("/opt/lab/sample.bin", sha("1"), 10)
	if len(lines) != 0 || quarantined != 0 {
		t.Fatalf("excluded file: %v quarantined=%d", lines, quarantined)
	}
	fc.Check("/tmp/sample.bin", sha("1"), 10)
	if len(lines) != 1 || quarantined != 1 {
		t.Fatalf("not excluded: %v quarantined=%d", lines, quarantined)
	}
}
