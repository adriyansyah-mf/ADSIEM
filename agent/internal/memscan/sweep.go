package memscan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// LogType of the periodic RWX sweep (decoders/process_memory_rwx.yaml).
const LogType = "process_memory_rwx"

// Sweeper reports writable+executable private memory across all
// processes, once per region (pid, start) while it exists.
type Sweeper struct {
	Push     func(logType, line string)
	Interval time.Duration
	seen     map[string]bool

	// procs and regions default to Processes and SuspiciousRegions (tests
	// replace them).
	procs   func() ([]Proc, error)
	regions func(pid int) ([]Region, error)
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// RWXLine encodes one suspicious region.
func RWXLine(p Proc, r Region) string {
	return fmt.Sprintf(`Image=%s PID=%d Address=%s Size=%d Perms=%s Kind=%s Path=%s`,
		kv(p.Image), p.PID, hexAddr(r.Start), r.Size(), r.Perms, r.Kind, kv(r.Path))
}

// Sweep checks every process once and returns the regions reported.
func (s *Sweeper) Sweep() int {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if s.procs == nil {
		s.procs, s.regions = Processes, SuspiciousRegions
	}
	procs, err := s.procs()
	if err != nil {
		slog.Warn("memscan: cannot list processes", "err", err)
		return 0
	}
	self := os.Getpid()
	current := map[string]bool{}
	reported := 0
	for _, p := range procs {
		if p.PID == self {
			continue
		}
		regions, err := s.regions(p.PID)
		if err != nil {
			continue
		}
		for _, r := range regions {
			key := fmt.Sprintf("%d|%x", p.PID, r.Start)
			current[key] = true
			if s.seen[key] {
				continue
			}
			s.Push(LogType, RWXLine(p, r))
			reported++
		}
	}
	// Forget regions that are gone, so a new one at the same address
	// counts. The set is as large as the RWX regions that exist.
	s.seen = current
	return reported
}

// Run sweeps every Interval (default 5 minutes) until ctx ends.
func (s *Sweeper) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Interval = 5 * time.Minute
	}
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		n := s.Sweep()
		if n > 0 {
			slog.Info("memscan: writable+executable private memory", "new_regions", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
