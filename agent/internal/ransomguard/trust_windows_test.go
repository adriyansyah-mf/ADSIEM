//go:build windows

package ransomguard

import (
	"os"
	"path/filepath"
	"testing"
)

// The real Authenticode check: the unsigned test binary is not Microsoft's,
// nor is a copy of a signed file with one byte changed; an installed
// OneDrive (when the host has one) is.
func TestVerifyMicrosoftOnHost(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if verifyMicrosoft(self) {
		t.Fatalf("unsigned test binary %s verified as Microsoft", self)
	}
	var found string
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft OneDrive\OneDrive.exe`),
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\OneDrive\OneDrive.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			found = p
			break
		}
	}
	if found == "" {
		t.Skip("no OneDrive installed on this host")
	}
	if !verifyMicrosoft(found) {
		t.Fatalf("%s not verified as signed by Microsoft Corporation", found)
	}
	data, err := os.ReadFile(found)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2]++
	tampered := filepath.Join(t.TempDir(), "OneDrive.exe")
	os.WriteFile(tampered, data, 0o755)
	if verifyMicrosoft(tampered) {
		t.Fatal("a tampered copy verified")
	}
}
