//go:build !linux && !windows

package task

import (
	"errors"
)

func processesRunning(string) []int { return nil }

func hostTarget(path string) (string, error) { return path, nil }

func preflightQuarantine(string) error {
	return errors.New("quarantine_file requires Linux or Windows")
}

func assertQuarantinable(string) error {
	return errors.New("quarantine_file requires Linux or Windows")
}

func killProcess(pid int, force bool, graceSeconds float64) (KillResult, error) {
	return KillResult{}, errors.New("kill_process requires Linux or Windows")
}

func quarantineFile(path string) (QuarantineRecord, error) {
	return QuarantineRecord{}, errors.New("quarantine_file requires Linux or Windows")
}

func restoreFile(path string) (QuarantineRecord, error) {
	return QuarantineRecord{}, errors.New("restore_file requires Linux or Windows")
}
