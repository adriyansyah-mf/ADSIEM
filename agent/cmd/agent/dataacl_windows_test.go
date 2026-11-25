//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func daclSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read DACL of %s: %v", path, err)
	}
	return sd.String()
}

func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("set DACL of %s: %v", path, err)
	}
}

// protectDataDir replaces whatever DACL the data dir had (here an extra
// Everyone ACE) with a protected one for SYSTEM and Administrators only,
// inheritable on the dir, and the same on config.yaml. Only a temp dir.
func TestProtectDataDirReplacesDACL(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid.String()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("agent: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test owns both, so it keeps WRITE_DAC and can always give itself
	// access back for t.TempDir's cleanup, elevated or not.
	t.Cleanup(func() {
		setDACL(t, dir, "D:(A;OICI;FA;;;"+me+")")
		setDACL(t, cfg, "D:(A;;FA;;;"+me+")")
	})
	setDACL(t, dir, "D:(A;OICI;FA;;;WD)(A;OICI;FA;;;"+me+")")
	setDACL(t, cfg, "D:(A;;FA;;;WD)(A;;FA;;;"+me+")")

	if err := protectDataDir(cfg); err != nil {
		t.Fatalf("protectDataDir: %v", err)
	}
	for path, want := range map[string]string{dir: "OICI", cfg: ""} {
		got := daclSDDL(t, path)
		if !strings.HasPrefix(got, "D:P") {
			t.Errorf("%s: DACL not protected: %s", path, got)
		}
		if strings.Contains(got, ";WD)") || strings.Contains(got, me) {
			t.Errorf("%s: old ACEs kept: %s", path, got)
		}
		for _, sid := range []string{"SY", "BA"} {
			if !strings.Contains(got, "(A;"+want+";FA;;;"+sid+")") {
				t.Errorf("%s: no full access for %s (flags %q): %s", path, sid, want, got)
			}
		}
	}
}

func TestProtectDataDirWithoutConfigFile(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Cleanup(func() { setDACL(t, dir, "D:(A;OICI;FA;;;"+user.User.Sid.String()+")") })
	if err := protectDataDir(filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatalf("protectDataDir: %v", err)
	}
	if got := daclSDDL(t, dir); !strings.HasPrefix(got, "D:P") {
		t.Fatalf("DACL not protected: %s", got)
	}
}
