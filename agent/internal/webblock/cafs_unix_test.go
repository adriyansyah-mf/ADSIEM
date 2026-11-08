//go:build !windows

package webblock

import (
	"os"
	"path/filepath"
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

func TestCADirSymlinkRefused(t *testing.T) {
	state := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, caDir(state)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCA(state, "h"); err == nil {
		t.Fatal("symlinked CA dir accepted")
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("wrote through the symlink: %v", ents)
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
