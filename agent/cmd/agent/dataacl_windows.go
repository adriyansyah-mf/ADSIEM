//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The data directory (config.yaml with the agent token, agent.log, state)
// belongs to SYSTEM and Administrators only. The DACL is protected, so
// nothing is inherited from the parent; on the directory the ACEs are
// inherited by what it holds (OI: files, CI: subdirectories).
const (
	dataDirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	dataFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// protectDataDir sets a fresh protected DACL on the directory of configPath
// and on configPath itself (when it exists), replacing every ACE they had.
func protectDataDir(configPath string) error {
	dir := filepath.Dir(configPath)
	if err := setProtectedDACL(dir, dataDirSDDL); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if err := setProtectedDACL(configPath, dataFileSDDL); err != nil &&
		!errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	return nil
}

func setProtectedDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
