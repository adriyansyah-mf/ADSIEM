package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/siem-platform/agent/internal/evidence"
)

type EvidenceConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Dir           string `yaml:"dir"`
	MaxBytes      int64  `yaml:"max_bytes"`
	SegmentBytes  int64  `yaml:"segment_bytes"`
	ReservedBytes int64  `yaml:"reserved_bytes"`
	MaxEventBytes int    `yaml:"max_event_bytes"`
}

func (cfg *Config) defaultEvidence() error {
	if cfg.Agent.StateDir == "" {
		state, err := defaultStateDir()
		if err != nil {
			return fmt.Errorf("default state directory: %w", err)
		}
		cfg.Agent.StateDir = state
	}
	state, err := filepath.Abs(cfg.Agent.StateDir)
	if err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	cfg.Agent.StateDir = state
	e := &cfg.Evidence
	if e.Dir == "" {
		e.Dir = filepath.Join(state, "evidence")
	} else if !filepath.IsAbs(e.Dir) {
		e.Dir = filepath.Join(state, e.Dir)
	}
	if e.MaxBytes == 0 {
		e.MaxBytes = 1 << 30
	}
	if e.SegmentBytes == 0 {
		e.SegmentBytes = 16 << 20
	}
	if e.ReservedBytes == 0 {
		e.ReservedBytes = 16 << 20
	}
	if e.MaxEventBytes == 0 {
		e.MaxEventBytes = 1 << 20
	}
	options := evidence.Options{Dir: e.Dir, AgentID: cfg.Agent.ID, MaxBytes: e.MaxBytes, SegmentBytes: e.SegmentBytes, ReservedBytes: e.ReservedBytes, MaxEventBytes: e.MaxEventBytes}
	if err := options.Validate(); err != nil {
		return fmt.Errorf("evidence config: %w", err)
	}
	if !descendant(state, e.Dir) {
		return fmt.Errorf("evidence directory must be inside state directory: %w", evidence.ErrInvalidOptions)
	}
	resolvedState, err := resolveExisting(state)
	if err != nil {
		return fmt.Errorf("resolve state directory: %w", err)
	}
	resolvedDir, err := resolveExisting(e.Dir)
	if err != nil {
		return fmt.Errorf("resolve evidence directory: %w", err)
	}
	if !descendant(resolvedState, resolvedDir) {
		return fmt.Errorf("evidence directory escapes resolved state directory: %w", evidence.ErrInvalidOptions)
	}
	cfg.Agent.StateDir = resolvedState
	e.Dir = resolvedDir
	// derived from the canonical state directory, like the evidence directory
	// (on Windows a short 8.3 name and its long name are the same directory)
	if cfg.Buffer.SpillPath == "" {
		cfg.Buffer.SpillPath = filepath.Join(resolvedState, "spill.log")
	}
	if cfg.Firewall.StatePath == "" {
		cfg.Firewall.StatePath = filepath.Join(resolvedState, "firewall.json")
	}
	return nil
}

func descendant(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Resolve existing ancestors so validation works before first startup creates
// directories. EvalSymlinks also resolves Windows junctions/reparse links.
func resolveExisting(path string) (string, error) {
	_, err := os.Lstat(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return "", statErr
		}
		if !info.IsDir() {
			return "", fmt.Errorf("storage path is not a directory: %w", evidence.ErrInvalidOptions)
		}
		return filepath.EvalSymlinks(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolved, err := resolveExisting(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}
