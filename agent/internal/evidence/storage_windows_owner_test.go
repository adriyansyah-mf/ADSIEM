//go:build windows

package evidence

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsCreatesUserOwnedJournalWithGroupDefaultOwner(t *testing.T) {
	if os.Getenv("SIEM_EVIDENCE_GROUP_OWNER_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsCreatesUserOwnedJournalWithGroupDefaultOwner$")
		cmd.Env = append(os.Environ(), "SIEM_EVIDENCE_GROUP_OWNER_CHILD=1")
		output, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 77 {
			t.Skip("native prerequisite: enabled owner-capable group distinct from TokenUser is unavailable")
		}
		if err != nil {
			t.Fatalf("isolated group-owner regression: %v\n%s", err, output)
		}
		return
	}
	// Given an isolated child token with a different, already-enabled valid owner.
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := token.Close(); err != nil {
			t.Error(err)
		}
	}()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	var group *windows.SID
	for _, candidate := range groups.AllGroups() {
		flags := uint32(windows.SE_GROUP_ENABLED | windows.SE_GROUP_OWNER)
		if candidate.Attributes&flags == flags && candidate.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 && candidate.Sid.String() != user.User.Sid.String() {
			group = candidate.Sid
			break
		}
	}
	if group == nil {
		os.Exit(77)
	}
	o := journalOptions(t)
	previous := windowsTestTokenOwner(t, token)
	if err := setWindowsTestTokenOwner(token, group); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := setWindowsTestTokenOwner(token, previous); err != nil {
			t.Error(err)
		}
	}()
	if actual := windowsTestTokenOwner(t, token); actual.String() != group.String() || actual.String() == user.User.Sid.String() {
		t.Fatalf("TokenOwner fixture differs from requested group: %s", actual.String())
	}
	// When fresh journal state is created despite the group's default ownership.
	j := openJournal(t, o)
	e := journalEvent(t, o)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	// Then directory, lock and segment are owned by TokenUser and can reopen.
	for _, path := range []string{o.Dir, filepath.Join(o.Dir, "owner.lock"), firstSegment(t, o)} {
		if owner := windowsTestObjectOwner(t, path); owner != user.User.Sid.String() {
			t.Fatalf("journal owner %s: %s", path, owner)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != e.EventID {
		t.Fatalf("group-token reopen: %v %v", ok, err)
	}
	// Existing foreign-owned state remains rejected, without taking ownership.
	foreign := filepath.Join(filepath.Dir(o.Dir), "group-owned-existing")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if owner := windowsTestObjectOwner(t, foreign); owner != group.String() {
		t.Fatalf("default-owner fixture: %s", owner)
	}
	o.Dir = foreign
	other, err := Open(o)
	if other != nil {
		if err := other.Close(); err != nil {
			t.Error(err)
		}
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("foreign-owned existing directory accepted: %v", err)
	}
	if owner := windowsTestObjectOwner(t, foreign); owner != group.String() {
		t.Fatalf("existing owner changed: %s", owner)
	}
}

type windowsTestOwner struct{ Owner *windows.SID }

func windowsTestTokenOwner(t *testing.T, token windows.Token) *windows.SID {
	t.Helper()
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size); !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		t.Fatalf("size TokenOwner: %v", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		t.Fatal(err)
	}
	// The API returns TOKEN_OWNER followed by its SID in this borrowed buffer.
	owner := (*windowsTestOwner)(unsafe.Pointer(&buffer[0])).Owner
	copy, err := owner.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return copy
}

func setWindowsTestTokenOwner(token windows.Token, sid *windows.SID) error {
	owner := windowsTestOwner{Owner: sid}
	return windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)))
}

func windowsTestObjectOwner(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return owner.String()
}
