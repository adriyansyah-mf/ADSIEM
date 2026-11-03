//go:build windows

package scriptscan

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// KillProcess stops a process (block mode).
func KillProcess(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
