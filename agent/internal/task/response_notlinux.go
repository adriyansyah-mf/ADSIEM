//go:build !linux

package task

import (
	"errors"
)

type KillResult struct {
	Refused string `json:"refused,omitempty"`
}

type QuarantineRecord struct{}

func killProcess(pid int, force bool, graceSeconds float64) (KillResult, error) {
	return KillResult{}, errors.New("kill_process requires Linux")
}

func quarantineFile(path string) (QuarantineRecord, error) {
	return QuarantineRecord{}, errors.New("quarantine_file requires Linux")
}

func restoreFile(path string) (QuarantineRecord, error) {
	return QuarantineRecord{}, errors.New("restore_file requires Linux")
}

func setQuarantineStore(path string) {}

type IntegrityReport struct{}

func CheckIntegrity(configPath, stateDir string) (IntegrityReport, error) {
	return IntegrityReport{}, errors.New("agent_integrity requires Linux")
}
