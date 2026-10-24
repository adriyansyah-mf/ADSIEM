//go:build windows

package evidence

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

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
	if owner.String() != d.owner {
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
