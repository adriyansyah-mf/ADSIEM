//go:build linux

package task

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Quarantine makes a file unreadable and immutable without deleting it, so an
// analyst can still recover it (QuarantineRecord, quarantine_store.go).

var quarantineProtectedDirs = []string{"/proc", "/sys", "/dev", "/boot"}

func quarantineFile(path string) (QuarantineRecord, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return QuarantineRecord{}, err
	}
	if err := assertQuarantinable(abs); err != nil {
		return QuarantineRecord{}, err
	}

	info, err := os.Lstat(abs)
	if err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: %w", err)
	}
	if err := checkQuarantineTarget(abs, info); err != nil {
		return QuarantineRecord{}, err
	}

	sum, err := hashFile(abs)
	if err != nil {
		return QuarantineRecord{}, err
	}

	rec := QuarantineRecord{
		Path:          abs,
		OriginalMode:  info.Mode().Perm(),
		Size:          info.Size(),
		SHA256:        sum,
		QuarantinedAt: time.Now().UTC(),
	}

	if err := os.Chmod(abs, 0); err != nil {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: chmod: %w", err)
	}
	if err := chattrImmutable(abs, true); err == nil {
		rec.Immutable = true
	}

	qStore.mu.Lock()
	qStore.load()[abs] = rec
	qStore.save()
	qStore.mu.Unlock()

	return rec, nil
}

func restoreFile(path string) (QuarantineRecord, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return QuarantineRecord{}, err
	}

	qStore.mu.Lock()
	defer qStore.mu.Unlock()

	rec, ok := qStore.load()[abs]
	if !ok {
		return QuarantineRecord{}, fmt.Errorf("restore_file: %s is not quarantined", abs)
	}

	if rec.Immutable {
		_ = chattrImmutable(abs, false)
	}
	if err := os.Chmod(abs, rec.OriginalMode); err != nil {
		return QuarantineRecord{}, fmt.Errorf("restore_file: chmod: %w", err)
	}

	sum, err := hashFile(abs)
	if err == nil && sum != rec.SHA256 {
		slog.Warn("restored file content differs from quarantine hash",
			"path", abs, "expected", rec.SHA256, "actual", sum)
	}

	delete(qStore.entries, abs)
	qStore.save()
	return rec, nil
}

// preflightQuarantine refuses, before any process is stopped, a target that
// quarantine would refuse or that would hit more than the file: a directory,
// a symlink (stat follows it, so its target's processes would be stopped), or
// a root-owned file with other hard links (chmod 0 and chattr +i lock the
// inode, so every name of it: a dropped link to /usr/bin/x would disable x).
// A file another user owns is quarantined whatever its links: an attacker
// cannot link files it does not own (protected_hardlinks), and must not dodge
// quarantine with a link of its own. A missing file passes: the programs still
// running it are stopped, and quarantine then reports it gone.
func preflightQuarantine(abs string) error {
	info, err := os.Lstat(abs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("quarantine_file: %w", err)
	}
	return checkQuarantineTarget(abs, info)
}

func checkQuarantineTarget(abs string, info os.FileInfo) error {
	switch {
	case info.IsDir():
		return fmt.Errorf("quarantine_file: %s is a directory", abs)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("quarantine_file: %s is a symlink", abs)
	case !info.Mode().IsRegular():
		return fmt.Errorf("quarantine_file: %s is not a regular file", abs)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 && st.Uid == 0 {
		return fmt.Errorf("quarantine_file: %s is a root-owned file with %d hard links; locking it would lock every link "+
			"(it may be a system binary): remove the extra link or quarantine by hash", abs, st.Nlink)
	}
	return nil
}

func assertQuarantinable(abs string) error {
	for _, dir := range quarantineProtectedDirs {
		if abs == dir || strings.HasPrefix(abs, dir+string(os.PathSeparator)) {
			return fmt.Errorf("quarantine_file: %s is under a protected pseudo-filesystem", abs)
		}
	}
	if abs == "/" {
		return fmt.Errorf("quarantine_file: refusing to quarantine the root directory")
	}
	if filepath.Base(abs) == ".ssh" {
		return fmt.Errorf("quarantine_file: refusing to quarantine an SSH directory")
	}
	return nil
}

func chattrImmutable(path string, on bool) error {
	flag := "+i"
	if !on {
		flag = "-i"
	}
	out, err := exec.Command("chattr", flag, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("chattr %s: %s: %w", flag, strings.TrimSpace(string(out)), err)
	}
	return nil
}
