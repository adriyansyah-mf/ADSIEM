//go:build !windows

package webblock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// secureDir makes sure dir exists as a private directory owned by this
// process: not a symlink, owned by euid, no group/other bits.
func secureDir(dir string) error {
	fi, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		fi, err = os.Lstat(dir)
		if err == nil && fi.Mode()&os.ModeSymlink == 0 {
			err = os.Chmod(dir, 0o700)
		}
		if err == nil {
			fi, err = os.Lstat(dir)
		}
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("webblock: %s is not a plain directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("webblock: %s is not owned by the agent user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// writeSecretFile writes dir/name through a random temp file (0600) in the
// private directory, fsyncs it and renames it into place.
func writeSecretFile(dir, name string, data []byte) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// checkSecretFile requires path, when present, to be a regular file (no
// symlink) owned by the agent user.
func checkSecretFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("webblock: %s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("webblock: %s is not owned by the agent user", path)
	}
	return nil
}
