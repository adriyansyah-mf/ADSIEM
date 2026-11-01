//go:build windows

package ransomguard

import "golang.org/x/sys/windows"

// prepareWrite clears the attributes of an existing canary: CreateFile
// with CREATE_ALWAYS (os.WriteFile) and DeleteFile fail with access denied
// on a hidden or read-only file.
func prepareWrite(path string) {
	if p, err := windows.UTF16PtrFromString(path); err == nil {
		windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_NORMAL)
	}
}

// hideFile sets the hidden attribute, which Explorer honours by default.
// Not the system attribute: it hides the file even from users who show
// hidden files, and some ransomware skips system files.
func hideFile(path string) {
	if p, err := windows.UTF16PtrFromString(path); err == nil {
		windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_HIDDEN)
	}
}
