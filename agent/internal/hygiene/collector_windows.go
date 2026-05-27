//go:build windows

package hygiene

import (
	"runtime"
	"time"
)

func Collect(agentID, hostname string) (*Report, error) {
	// Stub: hygiene collection not implemented on Windows.
	r := &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		OSName:      "Windows",
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		CPUCount:    runtime.NumCPU(),
		Score:       0,
	}
	return r, nil
}
