//go:build windows

package evidence

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func (d *storageDir) remove(name string) error {
	if filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `:/\`) {
		return os.ErrPermission
	}
	f, err := d.ntOpen(ntOpen{name: name, parent: windows.Handle(d.file.Fd()), disposition: windows.FILE_OPEN, access: windows.DELETE | windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.WRITE_DAC | windows.READ_CONTROL})
	if err != nil {
		return err
	}
	if err := d.restrict(f); err != nil {
		return errors.Join(err, f.Close())
	}
	// FILE_DISPOSITION_INFO is one BOOLEAN. This pinned relative handle owns the
	// deletion; no path re-resolution, replacement, or open-file rename is used.
	deleteFile := byte(1)
	return errors.Join(windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &deleteFile, 1), f.Close())
}
