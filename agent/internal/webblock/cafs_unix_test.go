//go:build !windows

package webblock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCADirAndKeyModes(t *testing.T) {
	_, dir := newTestCA(t)
	st, err := os.Stat(caDir(dir))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v %v", st, err)
	}
	st, err = os.Stat(keyPath(dir))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v %v", st, err)
	}
	ents, _ := os.ReadDir(caDir(dir))
	if len(ents) != 2 {
		t.Fatalf("temp files left: %v", ents)
	}
}

func TestCADirSymlinkMovedAside(t *testing.T) {
	state := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, caDir(state)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCA(state, "h"); err != nil {
		t.Fatalf("CA not created after moving the symlink aside: %v", err)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("wrote through the symlink: %v", ents)
	}
	fi, err := os.Lstat(caDir(state))
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o700 {
		t.Fatalf("not recreated as a private directory: %v %v", fi, err)
	}
	aside, _ := filepath.Glob(caDir(state) + ".untrusted-*")
	if len(aside) != 1 {
		t.Fatalf("aside %v", aside)
	}
	if l, err := os.Readlink(aside[0]); err != nil || l != target {
		t.Fatalf("the symlink itself was not moved aside: %q %v", l, err)
	}
}

func TestListDirSymlinkMovedAside(t *testing.T) {
	state := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, caDir(state)); err != nil {
		t.Fatal(err)
	}
	l := Empty()
	l.Version = "g:1"
	if err := l.Save(ListPath(state)); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("wrote through the symlink: %v", ents)
	}
	st, err := os.Stat(ListPath(state))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("list mode %v %v", st, err)
	}
}

// A directory owned by another user can only be made as root; without root
// the case is covered by the same untrustedDir check as the symlink.
func TestCADirForeignOwnerMovedAside(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a directory owned by another user")
	}
	state := t.TempDir()
	if err := os.Mkdir(caDir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(caDir(state), 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(caDir(state)); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Lstat(caDir(state))
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Geteuid() {
		t.Fatalf("still foreign-owned: uid %d", st.Uid)
	}
	if aside, _ := filepath.Glob(caDir(state) + ".untrusted-*"); len(aside) != 1 {
		t.Fatalf("aside %v", aside)
	}
}

func TestListLoadRefusesSymlinkedFile(t *testing.T) {
	state := t.TempDir()
	real := filepath.Join(t.TempDir(), "list.json")
	os.WriteFile(real, []byte(`{"version":"x"}`), 0o600)
	os.MkdirAll(caDir(state), 0o700)
	if err := os.Symlink(real, ListPath(state)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ListPath(state)); err == nil {
		t.Fatal("symlinked list loaded")
	}
}

func TestCADirLoosePermissionsFixed(t *testing.T) {
	ca, state := newTestCA(t)
	if err := os.Chmod(caDir(state), 0o775); err != nil {
		t.Fatal(err)
	}
	again, created, err := LoadOrCreateCA(state, "h")
	if err != nil || created || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload: %v", err)
	}
	st, _ := os.Stat(caDir(state))
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode not fixed: %v", st.Mode())
	}
}

func skipIfNotElevated(t *testing.T) {}

func TestCASymlinkedKeyRefused(t *testing.T) {
	_, state := newTestCA(t)
	real := filepath.Join(t.TempDir(), "k")
	b, _ := os.ReadFile(keyPath(state))
	os.WriteFile(real, b, 0o600)
	os.Remove(keyPath(state))
	if err := os.Symlink(real, keyPath(state)); err != nil {
		t.Fatal(err)
	}
	if _, created, err := LoadOrCreateCA(state, "host1"); err == nil || created {
		t.Fatalf("symlinked key accepted: %v created=%v", err, created)
	}
}
