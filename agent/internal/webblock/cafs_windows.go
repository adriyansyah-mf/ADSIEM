//go:build windows

package webblock

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// secureDir creates dir with a protected SYSTEM+Administrators DACL (so it is
// never open to other users, even briefly), or verifies and re-applies that
// DACL on an existing one. Reparse points and foreign owners are refused.
func secureDir(dir string) error {
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
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("webblock: %s is not a plain directory", dir)
	}
	osd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := osd.Owner()
	if err != nil {
		return err
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("webblock: %s has an unexpected owner", dir)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
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
