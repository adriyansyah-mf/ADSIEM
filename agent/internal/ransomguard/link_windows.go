//go:build windows

package ransomguard

import (
	"os"

	"golang.org/x/sys/windows"
)

// isLink reports whether path itself is a junction or symbolic link: a
// reparse point whose tag is a name surrogate (it names another path). Other
// reparse points, such as OneDrive Files On-Demand folders, are real
// directories and keep their canaries.
func isLink(path string) bool {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false
	}
	var fd windows.Win32finddata
	h, err := windows.FindFirstFile(p, &fd)
	if err != nil {
		return true // a reparse point we cannot read: do not plant through it
	}
	windows.FindClose(h)
	const nameSurrogate = 0x20000000 // IsReparseTagNameSurrogate
	return fd.Reserved0&nameSurrogate != 0
}
