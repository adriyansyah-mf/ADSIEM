//go:build !windows

package task

import (
	"io/fs"
	"strconv"
	"syscall"
)

// fileOwnerUID is the numeric owner of a file ("" if unknown).
func fileOwnerUID(info fs.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return strconv.Itoa(int(st.Uid))
	}
	return ""
}
