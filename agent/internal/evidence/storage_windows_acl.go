//go:build windows

package evidence

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// trustedOwner accepts the principals the restricted DACL already trusts: the
// agent's own token user, LocalSystem and BUILTIN\Administrators. An elevated
// administrator creating or restoring state files gets the Administrators
// group as owner by default; anyone else is refused.
func trustedOwner(owner, tokenUser string) bool {
	switch owner {
	case tokenUser, "S-1-5-18", "S-1-5-32-544":
		return true
	}
	return false
}

func (d *storageDir) restrict(f *os.File) error {
	h := windows.Handle(f.Fd())
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !trustedOwner(owner.String(), d.owner) {
		return fmt.Errorf("journal object owner: %w", os.ErrPermission)
	}
	acl, _, err := d.security.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	// File.Sync also persists repaired file ACL metadata; directories use volume
	// flush at namespace boundaries because directory flushing is not portable.
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if err := f.Sync(); err != nil {
			return errors.Join(ErrUnsupported, err)
		}
	}
	return nil
}
