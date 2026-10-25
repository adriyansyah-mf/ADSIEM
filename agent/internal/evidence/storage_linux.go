//go:build linux

package evidence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type storageDir struct{ file *os.File }

func openStorageDir(path string) (_ *storageDir, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if abs == "/" {
		return nil, fmt.Errorf("root evidence directory: %w", ErrInvalidOptions)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "/")
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		child, openErr := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkErr := unix.Mkdirat(int(f.Fd()), part, 0700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				return nil, mkErr
			}
			child, openErr = unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr == nil {
				if syncErr := f.Sync(); syncErr != nil {
					return nil, errors.Join(syncErr, unix.Close(child))
				}
			}
		}
		if openErr != nil {
			return nil, fmt.Errorf("directory component %s: %w", part, openErr)
		}
		next := os.NewFile(uintptr(child), part)
		if closeErr := f.Close(); closeErr != nil {
			return nil, errors.Join(closeErr, next.Close())
		}
		f = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("journal directory owner: %w", os.ErrPermission)
	}
	if err := f.Chmod(0700); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return &storageDir{file: f}, nil
}

func (d *storageDir) open(name string, flags int) (_ *os.File, err error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, os.ErrPermission
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("unsafe journal file %s: %w", name, os.ErrPermission)
	}
	if err := f.Chmod(0600); err != nil {
		return nil, err
	}
	return f, nil
}

func (d *storageDir) names() ([]string, error) {
	// A fresh descriptor avoids retaining a directory stream offset across calls.
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), ".")
	names, err := f.Readdirnames(-1)
	return names, errors.Join(err, f.Close())
}

func (d *storageDir) lock() (*os.File, error) {
	f, err := d.open("owner.lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			err = errors.Join(ErrLocked, err)
		}
		return nil, errors.Join(err, f.Close())
	}
	if err := errors.Join(f.Sync(), d.sync()); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func (d *storageDir) sync() error  { return d.file.Sync() }
func (d *storageDir) close() error { return d.file.Close() }
