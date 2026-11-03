package yarascan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Skip (group policy: on-access YARA off, or the path excluded) leaves the
// YARA scan out but still hands the file to OnHash (the known-malware check).
func TestSkipLeavesYaraOutButNotTheHash(t *testing.T) {
	var out lines
	hashed := 0
	skip := true
	s := New(Options{Roots: []string{t.TempDir()}, Push: out.push,
		OnHash: func(string, string, int64, string) bool { hashed++; return false },
		Skip:   func(string) bool { return skip }})
	if errs := s.SetRules("h1", []Rule{{Name: "pack", Content: evilRule}}); len(errs) != 0 {
		t.Fatal(errs)
	}
	p := filepath.Join(t.TempDir(), "shell.php")
	os.WriteFile(p, []byte(`<?php eval($_POST["c"]); ?>`), 0o644)
	if m, _ := s.ScanPath(context.Background(), p, "on_access"); len(m) != 0 || len(out.snapshot()) != 0 || hashed != 1 {
		t.Fatalf("skipped: matches=%d lines=%d hashed=%d", len(m), len(out.snapshot()), hashed)
	}
	skip = false
	os.WriteFile(p, []byte(`<?php eval($_POST["d"]); ?>`), 0o644) // new content: scanned again
	if m, _ := s.ScanPath(context.Background(), p, "on_access"); len(m) != 1 {
		t.Fatalf("not skipped: matches=%d", len(m))
	}
}
