//go:build !linux

package hygiene

import (
	"errors"
	"runtime"
	"time"
)

// Collect reports that hygiene collection is unavailable on this platform.
// The Linux implementation reads /proc and calls syscall.Statfs, neither of
// which exists off Linux; the agent still builds and runs for log tailing.
func Collect(agentID, hostname string) (*Report, error) {
	return &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}, errors.New("hygiene: collection is only supported on Linux")
}
