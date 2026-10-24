//go:build linux

package evidence

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func (d *storageDir) remove(name string) error {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return os.ErrPermission
	}
	return unix.Unlinkat(int(d.file.Fd()), name, 0)
}
