package task

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// QuarantineRecord is what quarantine_file did to one file, kept in the
// agent's own state file (not on the target: an attacker able to write next
// to the file could otherwise rewrite it) so restore_file can undo exactly
// that. Linux records the mode and the immutable flag; Windows the security
// descriptor it replaced.
type QuarantineRecord struct {
	Path          string      `json:"path"`
	OriginalMode  os.FileMode `json:"original_mode"`
	Size          int64       `json:"size"`
	SHA256        string      `json:"sha256"`
	Immutable     bool        `json:"immutable"`
	QuarantinedAt time.Time   `json:"quarantined_at"`
	// Windows: the DACL (SDDL) and owner the file had before it was locked
	// to SYSTEM, and whether the owner could be moved to SYSTEM as well.
	OriginalDACL  string `json:"original_dacl,omitempty"`
	OriginalOwner string `json:"original_owner,omitempty"`
	OwnerChanged  bool   `json:"owner_changed,omitempty"`
}

// KillResult is what kill_process did. On Windows Signal is
// "TerminateProcess": there is no polite stop for an arbitrary process.
type KillResult struct {
	PID     int    `json:"pid"`
	Comm    string `json:"comm"`
	Image   string `json:"image,omitempty"`
	Signal  string `json:"signal"`
	Forced  bool   `json:"forced"`
	Exited  bool   `json:"exited"`
	WaitMS  int64  `json:"wait_ms"`
	Refused string `json:"refused,omitempty"`
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
