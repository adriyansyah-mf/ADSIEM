package ransomguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The signature check is cached per path, size and modification time: a
// binary replaced in place is checked again.
func TestSignatureCacheKeyedByFileState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "OneDrive.exe")
	os.WriteFile(p, []byte("v1"), 0o755)
	calls := 0
	verdict := true
	c := newSignCache(func(string) bool { calls++; return verdict })
	if !c.signed(p) || !c.signed(p) || calls != 1 {
		t.Fatalf("calls = %d, want 1 (cached)", calls)
	}
	verdict = false
	os.WriteFile(p, []byte("replaced"), 0o755)
	os.Chtimes(p, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if c.signed(p) || calls != 2 {
		t.Fatalf("replaced binary: calls = %d, still trusted = %t", calls, c.signed(p))
	}
	if c.signed(filepath.Join(t.TempDir(), "missing.exe")) {
		t.Fatal("a missing file is trusted")
	}
}
