// Package rulecache keeps the last rule set the server sent (exec
// prevention, YARA) on disk, so an agent that starts while the server is
// unreachable enforces those rules instead of none.
//
// The file is tamper-evident, not signed: a checksum over the rules catches
// a truncated or edited file, which is then ignored. Someone who can write
// the agent's state directory can already stop the agent.
package rulecache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type file struct {
	Hash     string          `json:"hash"`
	Checksum string          `json:"checksum"` // sha256 of Rules
	Rules    json.RawMessage `json:"rules"`
}

// Save writes hash and rules to path (0600, atomically).
func Save(path, hash string, rules any) error {
	raw, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	data, err := json.Marshal(file{Hash: hash, Checksum: checksum(raw), Rules: raw})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ErrNone: there is no cache file.
var ErrNone = errors.New("no cached rules")

// Load reads the cache into rules and returns its hash. A missing file is
// ErrNone; a damaged one an error, and rules is left alone.
func Load(path string, rules any) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", ErrNone
	}
	if err != nil {
		return "", err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if f.Checksum != checksum(f.Rules) {
		return "", fmt.Errorf("%s: checksum mismatch, ignoring the cached rules", path)
	}
	if err := json.Unmarshal(f.Rules, rules); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return f.Hash, nil
}

func checksum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
