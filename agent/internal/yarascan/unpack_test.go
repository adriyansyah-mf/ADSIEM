package yarascan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A web shell inside a zip: the archive itself matches nothing, the entry
// does, and is reported as "archive|entry"; every entry is hashed too (the
// known-malware check) unless unpacking is off.
func TestScanPathLooksInsideArchives(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("site/shell.php")
	f.Write([]byte(`<?php eval($_POST["c"]); ?>`))
	w.Close()
	p := filepath.Join(t.TempDir(), "backup.zip")
	os.WriteFile(p, buf.Bytes(), 0o644)

	for _, off := range []bool{false, true} {
		var out lines
		var hashed []string
		s := New(Options{Roots: []string{t.TempDir()}, Push: out.push, NoUnpack: off,
			OnHash: func(path, _ string, _ int64, _ string) bool { hashed = append(hashed, path); return false }})
		s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}})
		matches, err := s.ScanPath(context.Background(), p, "on_access")
		if err != nil {
			t.Fatal(err)
		}
		got := out.snapshot()
		if off {
			if len(got) != 0 || len(matches) != 0 || len(hashed) != 1 {
				t.Fatalf("unpack off: lines %v hashed %v", got, hashed)
			}
			continue
		}
		inner := p + "|site/shell.php"
		if len(got) != 1 || !strings.Contains(got[0], `rule="webshell"`) || !strings.Contains(got[0], kv(inner)) ||
			len(matches) != 1 {
			t.Fatalf("lines %v", got)
		}
		if len(hashed) != 2 || hashed[0] != p || hashed[1] != inner {
			t.Fatalf("hashed %v", hashed)
		}
	}
}
