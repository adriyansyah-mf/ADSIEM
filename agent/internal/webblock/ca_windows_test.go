//go:build windows

package webblock

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func skipIfNotElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the CA directory is owned by Administrators; run this test elevated")
	}
}

func assertProtectedSYBA(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL not protected on %s: %v", path, err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("no DACL on %s: %v", path, err)
	}
	if acl.AceCount != 2 {
		t.Fatalf("%s has %d ACEs, want 2", path, acl.AceCount)
	}
	sy, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	ba, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	seenSY, seenBA := false, false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&0x1F01FF != 0x1F01FF {
			t.Fatalf("%s ACE %d is not allow/full control", path, i)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(sy):
			seenSY = true
		case sid.Equals(ba):
			seenBA = true
		default:
			t.Fatalf("%s grants access to %s", path, sid)
		}
	}
	if !seenSY || !seenBA {
		t.Fatalf("%s missing SY/BA ACE", path)
	}
}

func TestWindowsCAFilesProtected(t *testing.T) {
	skipIfNotElevated(t)
	state := t.TempDir()
	if _, _, err := LoadOrCreateCA(state, "h"); err != nil {
		t.Fatal(err)
	}
	assertProtectedSYBA(t, caDir(state))
	assertProtectedSYBA(t, keyPath(state))
	assertProtectedSYBA(t, certPath(state))
}
