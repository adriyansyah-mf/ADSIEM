//go:build windows

package evidence

import (
	"os"

	"golang.org/x/sys/windows"
)

// writeOwned writes a crash-simulation file the way the journal creates its
// own files: owned by the token user. A plain os.WriteFile from an elevated
// administrator is owned by BUILTIN\Administrators, which the journal
// (rightly) refuses as a foreign owner.
func writeOwned(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		user.User.Sid, nil, nil, nil)
}
