//go:build !windows

package webblock

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestApplyKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-hosts")
	link := filepath.Join(dir, "hosts")
	if err := os.WriteFile(target, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	h := &HostsFile{Path: link}
	if _, _, err := h.Apply([]string{"evil.example"}, false); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v %v", st, err)
	}
	if !strings.Contains(readFile(t, target), "127.84.0.1 evil.example") {
		t.Fatal("target lacks block")
	}
}

func TestApplyFallsBackToInPlaceOnEBUSY(t *testing.T) {
	old := renameFile
	defer func() { renameFile = old }()
	renameFile = func(_, _ string) error { return &os.LinkError{Op: "rename", Err: syscall.EBUSY} }
	h, _ := newHosts(t, "127.0.0.1 localhost\n")
	if _, _, err := h.Apply([]string{"evil.example"}, false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, h.Path)
	if !strings.HasPrefix(got, "127.0.0.1 localhost\n") || !strings.Contains(got, "127.84.0.1 www.evil.example") {
		t.Fatalf("in-place write wrong: %q", got)
	}
	if _, err := os.Stat(h.Path + ".adsiem.tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}
