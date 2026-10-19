//go:build !linux && !windows

package hygiene

import (
	"errors"
	"runtime"
	"time"
)

// Collect reports that hygiene collection is unavailable on this platform
// (Linux and Windows have collectors); the agent still builds and runs for log tailing.
func Collect(agentID, hostname string) (*Report, error) {
	return &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}, errors.New("hygiene: collection is only supported on Linux and Windows")
}

func platformIssues(*Report) []Issue { return nil }

var baselinePorts = map[int]bool{}
