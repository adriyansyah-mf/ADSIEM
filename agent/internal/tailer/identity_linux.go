//go:build linux

package tailer

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fileIdentity is the open file's device and inode: stable across renames,
// different for a new file created at the same path.
func fileIdentity(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("no stat data for file identity")
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}
