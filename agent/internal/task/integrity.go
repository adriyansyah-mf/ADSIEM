package task

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IntegrityReport compares the running binary and config against a baseline
// captured at first start. A mismatch means the endpoint changed underneath
// the agent: a replaced binary, an edited config, or both.
type IntegrityReport struct {
	BinaryPath     string `json:"binary_path"`
	BinaryHash     string `json:"binary_hash"`
	Recommended    string `json:"baseline_hash,omitempty"`
	BinaryMatch    bool   `json:"binary_match"`
	ConfigPath     string `json:"config_path"`
	ConfigHash     string `json:"config_hash"`
	ConfigBaseline string `json:"config_baseline,omitempty"`
	ConfigMatch    bool   `json:"config_match"`
	BaselineAt     string `json:"baseline_at,omitempty"`
	FirstRun       bool   `json:"first_run"`
	Changed        bool   `json:"changed"`
}

type integrityBaseline struct {
	BinaryHash string `json:"binary_hash"`
	ConfigHash string `json:"config_hash"`
	RecordedAt string `json:"recorded_at"`
}

func integrityPath(stateDir string) string {
	return filepath.Join(stateDir, "integrity.json")
}

func agentBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// CheckIntegrity hashes the binary and config and compares them with the
// stored baseline, creating the baseline on first run.
func CheckIntegrity(configPath, stateDir string) (IntegrityReport, error) {
	bin, err := agentBinaryPath()
	if err != nil {
		return IntegrityReport{}, fmt.Errorf("agent_integrity: resolve binary: %w", err)
	}

	rep := IntegrityReport{BinaryPath: bin, ConfigPath: configPath}

	binHash, err := hashFile(bin)
	if err != nil {
		return IntegrityReport{}, fmt.Errorf("agent_integrity: hash binary: %w", err)
	}
	rep.BinaryHash = binHash

	if abs, err := filepath.Abs(configPath); err == nil {
		cfgHash, err := hashFile(abs)
		if err == nil {
			rep.ConfigHash = cfgHash
		}
	}

	path := integrityPath(stateDir)
	var base integrityBaseline
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &base); err != nil {
			return IntegrityReport{}, fmt.Errorf("agent_integrity: baseline corrupt: %w", err)
		}
	} else {
		rep.FirstRun = true
	}

	if rep.FirstRun {
		base = integrityBaseline{
			BinaryHash: rep.BinaryHash,
			ConfigHash: rep.ConfigHash,
			RecordedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := writeBaseline(path, base); err != nil {
			return IntegrityReport{}, err
		}
		rep.BaselineAt = base.RecordedAt
		rep.BinaryMatch = true
		rep.ConfigMatch = true
		return rep, nil
	}

	rep.Recommended = base.BinaryHash
	rep.ConfigBaseline = base.ConfigHash
	rep.BaselineAt = base.RecordedAt
	rep.BinaryMatch = rep.BinaryHash == base.BinaryHash
	rep.ConfigMatch = rep.ConfigHash == base.ConfigHash
	rep.Changed = !rep.BinaryMatch || !rep.ConfigMatch

	return rep, nil
}

func writeBaseline(path string, base integrityBaseline) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("agent_integrity: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("agent_integrity: write baseline: %w", err)
	}
	return nil
}

// ResetIntegrityBaseline re-captures the current hashes. It exists so an
// operator can accept an intentional upgrade without disabling the check.
func ResetIntegrityBaseline(configPath, stateDir string) (IntegrityReport, error) {
	_ = os.Remove(integrityPath(stateDir))
	return CheckIntegrity(configPath, stateDir)
}
