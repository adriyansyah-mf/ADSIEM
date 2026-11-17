//go:build !windows

package rollback

import (
	"io/fs"
	"syscall"
)

type fileID struct{ dev, ino uint64 }

// idOf: hard links share device and inode, so a linked copy counts once.
func idOf(_ string, info fs.FileInfo) (fileID, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{uint64(st.Dev), uint64(st.Ino)}, true
}
