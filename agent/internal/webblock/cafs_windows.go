//go:build windows

package webblock

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

func secAttrs(sddl string) (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, sd, nil
}

// openNoFollow opens path itself (never through a reparse point) with the
// given access.
func openNoFollow(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// checkHandle refuses reparse points and wrong object kinds, and requires the
// owner to be SYSTEM or Administrators.
func checkHandle(h windows.Handle, path string, wantDir bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDir != wantDir {
		return fmt.Errorf("%w: %s is not a plain file or directory", errUntrusted, path)
	}
	osd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := osd.Owner()
	if err != nil {
		return err
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("%w: %s has an unexpected owner", errUntrusted, path)
	}
	return nil
}

// errUntrusted marks an object that is a reparse point, of the wrong kind or
// owned by someone other than SYSTEM/Administrators.
var errUntrusted = errors.New("webblock: untrusted")

// moveAside renames path (the entry itself: MoveFileEx never follows a
// reparse point) out of the way and logs it.
func moveAside(path string) error {
	aside := fmt.Sprintf("%s.untrusted-%d", path, time.Now().Unix())
	if _, err := os.Lstat(aside); err == nil {
		aside = fmt.Sprintf("%s.untrusted-%d", path, time.Now().UnixNano())
	}
	if err := os.Rename(path, aside); err != nil {
		return fmt.Errorf("webblock: %s is untrusted and could not be moved aside: %w", path, err)
	}
	slog.Warn("webblock: moved an untrusted state directory aside and recreated it", "path", path, "moved_to", aside)
	return nil
}

// secureDir creates dir with a protected SYSTEM+Administrators DACL (so it is
// never open to other users, even briefly), or verifies and re-applies that
// DACL on an existing one, all through one handle. A reparse point, a file or
// a directory with a foreign owner in its place is renamed aside to
// <dir>.untrusted-<unixtime> and the directory created afresh.
func secureDir(dir string) error {
	err := secureDirOnce(dir)
	if !errors.Is(err, errUntrusted) {
		return err
	}
	if err := moveAside(dir); err != nil {
		return err
	}
	return secureDirOnce(dir)
}

func secureDirOnce(dir string) error {
	sa, sd, err := secAttrs(dirSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	h, err := openNoFollow(dir, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err := checkHandle(h, dir, true); err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
}

// checkSecretFile requires path to be a plain file owned by SYSTEM or
// Administrators.
func checkSecretFile(path string) error {
	h, err := openNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return checkHandle(h, path, false)
}

// writeSecretFile creates a random-named temp file inside the protected
// directory with the restrictive DACL set at creation (no inherited ACL, no
// sharing), writes and flushes it, then moves it onto the final name.
func writeSecretFile(dir, name string, data []byte) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(rnd[:]))
	tp, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	sa, _, err := secAttrs(fileSDDL)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(tp, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), tmp)
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	dst, err := windows.UTF16PtrFromString(filepath.Join(dir, name))
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := windows.MoveFileEx(tp, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
