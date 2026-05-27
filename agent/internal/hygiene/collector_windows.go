//go:build windows

package hygiene

import (
	"runtime"
	"time"
)

func Collect(agentID, hostname string) (*Report, error) {
	r := &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		OSName:      "Windows",
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		CPUCount:    runtime.NumCPU(),
		Score:       100,
	}
	return r, nil
}
