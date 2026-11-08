//go:build !windows

package webblock

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// secureDir makes sure dir exists as a private directory owned by this
// process: not a symlink, owned by euid, no group/other bits. Something else
// in its place (a symlink, a file, a directory owned by another user) is
// renamed aside to <dir>.untrusted-<unixtime> and the directory recreated.
func secureDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err == nil && untrustedDir(fi) {
		if err := moveAside(dir); err != nil {
			return err
		}
		fi, err = os.Lstat(dir)
	}
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
	if untrustedDir(fi) {
		return fmt.Errorf("webblock: %s is not a private directory of the agent user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// untrustedDir: not a plain directory, or not owned by the agent user.
func untrustedDir(fi os.FileInfo) bool {
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return true
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) != os.Geteuid()
}

// moveAside renames path (the entry itself, never a symlink's target) out of
// the way and logs it.
func moveAside(path string) error {
	aside := fmt.Sprintf("%s.untrusted-%d", path, time.Now().Unix())
	if _, err := os.Lstat(aside); err == nil {
		aside = fmt.Sprintf("%s.untrusted-%d", path, time.Now().UnixNano())
	}
	if err := os.Rename(path, aside); err != nil {
		return fmt.Errorf("webblock: %s is untrusted and could not be moved aside: %w", path, err)
	}
	slog.Warn("webblock: moved an untrusted state directory aside and recreated it", "path", path, "moved_to", aside)
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
	// make the rename itself durable (best effort)
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
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
