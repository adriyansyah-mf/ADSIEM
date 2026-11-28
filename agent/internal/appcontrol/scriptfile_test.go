package appcontrol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteScriptUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	path, err := writeScript(dir, "Write-Output 'é'")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(path)) != "scripts" {
		t.Fatalf("script not under scripts/: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 3 || data[0] != 0xEF || data[1] != 0xBB || data[2] != 0xBF {
		t.Fatalf("no UTF-8 BOM: % x", data[:min(3, len(data))])
	}
	if string(data[3:]) != "Write-Output 'é'" {
		t.Fatalf("script body changed: %q", data[3:])
	}
}

func TestScriptFileRunnerOnlyOnWindows(t *testing.T) {
	r := ScriptFileRunner(t.TempDir())
	if (r == nil) != (os.Getenv("OS") != "Windows_NT") {
		t.Fatalf("runner nil=%v on this host", r == nil)
	}
}
