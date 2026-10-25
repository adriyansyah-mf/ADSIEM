package task

import (
	"path/filepath"
	"testing"
)

func TestGlobBraces(t *testing.T) {
	rx, err := globRegexp("C:/Users/*/Downloads/**/*.{exe,dll,ps1}")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"C:/Users/bob/Downloads/x/payload.exe": true,
		"C:/Users/bob/Downloads/a.ps1":         true,
		"C:/Users/bob/Downloads/a.txt":         false,
		"C:/Users/bob/Desktop/a.exe":           false,
		"C:/Users/bob/Downloads/a.exe.txt":     false,
	} {
		if got := rx.MatchString(path); got != want {
			t.Errorf("%s: got %v, want %v", path, got, want)
		}
	}
	// filepath.Dir: the walk root uses the OS separator (\home on Windows).
	if root := globRoot("/home/{a,b}/x"); root != filepath.FromSlash("/home") {
		t.Errorf("globRoot stops at a brace: got %q", root)
	}
	if rx, _ := globRegexp("/tmp/{unclosed"); !rx.MatchString("/tmp/{unclosed") {
		t.Error("an unclosed brace is literal")
	}
}
