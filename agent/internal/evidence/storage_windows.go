//go:build windows

package evidence

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type storageDir struct {
	file      *os.File
	ancestors []*os.File
	volume    windows.Handle
	security  *windows.SECURITY_DESCRIPTOR
	owner     string
}

func openStorageDir(path string) (_ *storageDir, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(abs)
	if len(volume) != 2 || volume[1] != ':' || abs == volume+`\` {
		return nil, fmt.Errorf("drive-letter directory required: %w", ErrUnsupported)
	}
	rootName, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return nil, err
	}
	if windows.GetDriveType(rootName) != windows.DRIVE_FIXED {
		return nil, fmt.Errorf("local fixed NTFS required: %w", ErrUnsupported)
	}
	d := &storageDir{}
	defer func() {
		if err != nil {
			err = errors.Join(err, d.close())
		}
	}()
	volumeName, err := windows.UTF16PtrFromString(`\\.\` + volume)
	if err != nil {
		return nil, err
	}
	d.volume, err = windows.CreateFile(volumeName, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		d.volume = 0
		return nil, fmt.Errorf("volume flush access requires SYSTEM/admin: %w: %w", ErrUnsupported, err)
	}
	var fs [32]uint16
	if err := windows.GetVolumeInformation(rootName, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return nil, err
	}
	if windows.UTF16ToString(fs[:]) != "NTFS" {
		return nil, fmt.Errorf("local fixed NTFS required: %w", ErrUnsupported)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	d.owner = user.User.Sid.String()
	// TokenOwner may be a group; new state must satisfy the TokenUser owner check.
	d.security, err = windows.SecurityDescriptorFromString("O:" + d.owner + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + d.owner + ")")
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(rootName, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	d.ancestors = append(d.ancestors, os.NewFile(uintptr(h), volume+`\`))
	parts := strings.Split(strings.TrimPrefix(abs, volume+`\`), `\`)
	for i, part := range parts {
		final := i == len(parts)-1
		f, err := d.openDirectory(part, final)
		if err != nil {
			return nil, err
		}
		if final {
			d.file = f
		} else {
			d.ancestors = append(d.ancestors, f)
		}
	}
	if err := d.sync(); err != nil {
		return nil, fmt.Errorf("flush namespace unsupported: %w: %w", ErrUnsupported, err)
	}
	return d, nil
}

func (d *storageDir) openDirectory(name string, final bool) (*os.File, error) {
	parent := windows.Handle(d.ancestors[len(d.ancestors)-1].Fd())
	request := ntOpen{name: name, parent: parent, disposition: windows.FILE_OPEN, directory: true}
	request.access = windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	if final {
		request.access |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.WRITE_DAC | windows.READ_CONTROL
	}
	f, err := d.ntOpen(request)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		request.disposition = windows.FILE_CREATE
		request.access = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.WRITE_DAC | windows.READ_CONTROL
		f, err = d.ntOpen(request)
		if errors.Is(err, os.ErrExist) {
			request.disposition = windows.FILE_OPEN
			f, err = d.ntOpen(request)
		}
		if err == nil {
			if syncErr := d.sync(); syncErr != nil {
				return nil, errors.Join(syncErr, f.Close())
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("directory component %s: %w", name, err)
	}
	if final {
		if err := d.restrict(f); err != nil {
			return nil, errors.Join(err, f.Close())
		}
	}
	return f, nil
}

func (d *storageDir) open(name string, flags int) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `:/\`) {
		return nil, os.ErrPermission
	}
	disposition := uint32(windows.FILE_OPEN)
	if flags&os.O_CREATE != 0 {
		disposition = windows.FILE_OPEN_IF
	}
	if flags&os.O_EXCL != 0 {
		disposition = windows.FILE_CREATE
	}
	f, err := d.ntOpen(ntOpen{name: name, parent: windows.Handle(d.file.Fd()), disposition: disposition, access: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.WRITE_DAC | windows.READ_CONTROL})
	if err != nil {
		return nil, err
	}
	if err := d.restrict(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if flags&os.O_APPEND != 0 {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return nil, errors.Join(err, f.Close())
		}
	}
	return f, nil
}

func (d *storageDir) names() ([]string, error) {
	// An empty native relative name reopens the parent directory itself. NT paths
	// do not normalize "." as Win32 paths do (see Go's OBJECT_ATTRIBUTES.init).
	f, err := d.ntOpen(ntOpen{name: "", parent: windows.Handle(d.file.Fd()), disposition: windows.FILE_OPEN, directory: true, access: windows.FILE_GENERIC_READ})
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	return names, errors.Join(err, f.Close())
}

func (d *storageDir) lock() (*os.File, error) {
	f, err := d.open("owner.lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			err = errors.Join(ErrLocked, err)
		}
		return nil, errors.Join(err, f.Close())
	}
	if err := errors.Join(f.Sync(), d.sync()); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// Volume flush establishes namespace durability. File flush alone is never used
// as a substitute for persisting new segment/forensic/directory names.
func (d *storageDir) sync() error { return windows.FlushFileBuffers(d.volume) }

func (d *storageDir) close() error {
	var errs []error
	if d.file != nil {
		errs = append(errs, d.file.Close())
	}
	for i := len(d.ancestors) - 1; i >= 0; i-- {
		errs = append(errs, d.ancestors[i].Close())
	}
	if d.volume != 0 {
		errs = append(errs, windows.CloseHandle(d.volume))
	}
	return errors.Join(errs...)
}

type ntOpen struct {
	name                string
	parent              windows.Handle
	disposition, access uint32
	directory           bool
}

func (d *storageDir) ntOpen(request ntOpen) (*os.File, error) {
	name, err := windows.NewNTUnicodeString(request.name)
	if err != nil {
		return nil, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: request.parent, ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: d.security}
	// SAFETY: the native API consumes only the fixed layout size of this struct.
	oa.Length = uint32(unsafe.Sizeof(oa))
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	if request.directory {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE | windows.FILE_WRITE_THROUGH
	}
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, request.access, &oa, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, request.disposition, options, 0, 0)
	if err != nil {
		var ntStatus windows.NTStatus
		if errors.As(err, &ntStatus) {
			err = ntStatus.Errno()
		}
		return nil, err
	}
	f := os.NewFile(uintptr(h), request.name)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!request.directory && info.NumberOfLinks != 1) {
		return nil, errors.Join(os.ErrPermission, f.Close())
	}
	return f, nil
}
