//go:build windows

package rollback

import (
	"io/fs"
	"syscall"
)

type fileID struct {
	vol        uint32
	idxHi, idx uint32
}

// idOf: hard links share the volume serial and file index, so a linked
// copy counts once.
func idOf(path string, _ fs.FileInfo) (fileID, bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fileID{}, false
	}
	h, err := syscall.CreateFile(p, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fileID{}, false
	}
	defer syscall.CloseHandle(h)
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &d); err != nil {
		return fileID{}, false
	}
	return fileID{d.VolumeSerialNumber, d.FileIndexHigh, d.FileIndexLow}, true
}
