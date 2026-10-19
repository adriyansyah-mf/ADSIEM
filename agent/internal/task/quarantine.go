//go:build linux

package task

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Quarantine makes a file unreadable and immutable without deleting it, so an
// analyst can still recover it. The original mode is recorded in the agent's
// own state file, not on the target, because an attacker with write access to
// the file's directory could otherwise rewrite the metadata.
type QuarantineRecord struct {
	Path        string    `json:"path"`
	OriginalMode os.FileMode `json:"original_mode"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	Immutable   bool      `json:"immutable"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

type quarantineStore struct {
	mu      sync.Mutex
	path    string
	entries map[string]QuarantineRecord
}

var qStore = &quarantineStore{}

func setQuarantineStore(path string) {
	qStore.mu.Lock()
	defer qStore.mu.Unlock()
	qStore.path = path
	qStore.entries = nil
}

func (s *quarantineStore) load() map[string]QuarantineRecord {
	if s.entries != nil {
		return s.entries
	}
	s.entries = map[string]QuarantineRecord{}
	if s.path == "" {
		return s.entries
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return s.entries
	}
	if err := json.Unmarshal(data, &s.entries); err != nil {
		slog.Warn("quarantine state unreadable, starting fresh", "err", err)
		s.entries = map[string]QuarantineRecord{}
	}
	return s.entries
}

func (s *quarantineStore) save() {
	if s.path == "" || s.entries == nil {
		return
	}
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		slog.Warn("quarantine state dir failed", "err", err)
		return
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		slog.Warn("quarantine state write failed", "err", err)
	}
}

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

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
