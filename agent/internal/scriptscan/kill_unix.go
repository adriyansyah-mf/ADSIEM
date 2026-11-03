//go:build !windows

package scriptscan

import "syscall"

// KillProcess stops a process (block mode).
func KillProcess(pid uint32) error { return syscall.Kill(int(pid), syscall.SIGKILL) }
