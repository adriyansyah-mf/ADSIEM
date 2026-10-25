//go:build linux

package task

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if info.IsDir() {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: %s is a directory", abs)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return QuarantineRecord{}, fmt.Errorf("quarantine_file: %s is a symlink", abs)
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
