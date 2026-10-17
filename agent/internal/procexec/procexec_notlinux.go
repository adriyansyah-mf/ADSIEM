//go:build !linux

// Package procexec streams process-exec events by attaching an eBPF program to
// tracepoint/syscalls/sys_enter_execve. That is Linux-only, so this file
// provides the same API on other platforms as a no-op: Start reports the
// feature as unavailable, which callers already treat as non-fatal.
package procexec

import (
	"errors"

	"github.com/siem-platform/agent/internal/buffer"
)

const LogType = "linux_process_exec"

type Monitor struct{}

func Start(buf *buffer.Buffer) (*Monitor, error) {
	return nil, errors.New("procexec: eBPF process-exec monitor is only supported on Linux")
}

func (m *Monitor) Stop() {}
