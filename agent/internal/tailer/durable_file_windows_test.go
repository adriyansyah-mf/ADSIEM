//go:build windows

package tailer

import (
	"os"

	"golang.org/x/sys/windows"
)

// openAppendShared opens path for appending the way a rotatable logger does:
// sharing delete, so the file can be renamed while this handle is open.
func openAppendShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.FILE_APPEND_DATA,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
