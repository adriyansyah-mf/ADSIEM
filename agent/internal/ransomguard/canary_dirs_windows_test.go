//go:build windows

package ransomguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A real NTFS junction, as C:\Users\All Users and C:\ProgramData\Documents
// are: skipped, so the directory behind it gets one canary.
func TestCanaryDirsSkipJunction(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "Public")
	os.Mkdir(public, 0o755)
	junction := filepath.Join(root, "Shared")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, public).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}
	if !isLink(junction) || isLink(public) {
		t.Fatalf("isLink: junction %t, real dir %t", isLink(junction), isLink(public))
	}
	c := newCanaries([]string{filepath.Join(root, "*")}, []string{".c.pdf"}, false)
	if n := c.plant(); n != 1 || !c.isCanary(filepath.Join(public, ".c.pdf")) {
		t.Fatalf("planted %d: %v", n, keys(c.files))
	}
	if bad := c.verify(); len(bad) != 0 {
		t.Fatalf("changed with nothing running: %v", bad)
	}
}
