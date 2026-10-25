//go:build !linux && !windows

package task

import (
	"errors"
)

func killProcess(pid int, force bool, graceSeconds float64) (KillResult, error) {
	return KillResult{}, errors.New("kill_process requires Linux or Windows")
}

func quarantineFile(path string) (QuarantineRecord, error) {
	return QuarantineRecord{}, errors.New("quarantine_file requires Linux or Windows")
}

func restoreFile(path string) (QuarantineRecord, error) {
	return QuarantineRecord{}, errors.New("restore_file requires Linux or Windows")
}
