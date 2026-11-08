//go:build !windows

package webblock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// renameFile is replaced in tests.
var renameFile = os.Rename

// writeHosts writes data to path through a temp file in the same directory
// and a rename. When the rename is refused because path is a mount point
// (bind-mounted /etc/hosts in containers: EBUSY, EXDEV) it writes in place.
func writeHosts(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".adsiem.tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameFile(tmp, path)
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
			err = writeInPlace(path, data)
		}
	}
	os.Remove(tmp)
	return err
}

func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
