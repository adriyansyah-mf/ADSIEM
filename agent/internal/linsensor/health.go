package linsensor

import (
	"fmt"
	"time"
)

// Tamper checks of the sensor itself, reported as LogHealth lines:
//
//   - the "self" map holds the agent's tgid; its events are skipped in the
//     kernel. Overwriting it (bpftool map update name self ...) with another
//     process's tgid hides that process, so it is re-read every 30 s,
//     restored, and reported (event=self_map_overwritten).
//   - every 5 minutes a child creates and removes a canary file; if the
//     sensor does not see it within canaryWait, its programs were detached
//     or its tracepoints stopped firing while the agent kept heartbeating
//     (event=sensor_blind, then event=sensor_recovered when it sees one
//     again). Only changes are reported.
const (
	selfCheckEvery = 30 * time.Second
	canaryEvery    = 5 * time.Minute
	canaryWait     = 15 * time.Second
)

// healthChecker is the canary's state. Not safe for concurrent use: the
// sensor's mutex guards it (the processor calls claim under it).
type healthChecker struct {
	now        func() time.Time
	canaryPath string

	started  time.Time // zero when no canary is in flight
	seen     bool
	blind    bool
	lastSeen time.Time
}

func newHealthChecker(canaryPath string) *healthChecker {
	return &healthChecker{now: time.Now, canaryPath: canaryPath}
}

// claim reports whether path is the canary (its events are not shipped),
// and records that the sensor saw it.
func (h *healthChecker) claim(path string) bool {
	if path != h.canaryPath {
		return false
	}
	if !h.started.IsZero() {
		h.seen, h.lastSeen = true, h.now()
	}
	return true
}

// start marks a canary in flight; abort forgets it (the child could not run).
func (h *healthChecker) start() { h.started, h.seen = h.now(), false }
func (h *healthChecker) abort() { h.started = time.Time{} }

// verdict, once canaryWait has passed since start, returns the line for a
// change of state: blind, or recovered. "" otherwise.
func (h *healthChecker) verdict() string {
	if h.started.IsZero() || h.now().Sub(h.started) < canaryWait {
		return ""
	}
	h.started = time.Time{}
	switch {
	case !h.seen && !h.blind:
		h.blind = true
		last := "never"
		if !h.lastSeen.IsZero() {
			last = h.lastSeen.UTC().Format(time.RFC3339)
		}
		return fmt.Sprintf(`event=sensor_blind check=canary waited_seconds=%d last_seen=%s canary=%s`,
			int(canaryWait.Seconds()), last, kv(h.canaryPath))
	case h.seen && h.blind:
		h.blind = false
		return fmt.Sprintf(`event=sensor_recovered check=canary canary=%s`, kv(h.canaryPath))
	}
	return ""
}

// selfLine reports the self map holding another tgid than the agent's.
func selfLine(expected, found uint32, restored bool, err error) string {
	l := fmt.Sprintf(`event=self_map_overwritten expected_tgid=%d found_tgid=%d restored=%t`, expected, found, restored)
	if err != nil {
		l += " error=" + kv(err.Error())
	}
	return l
}
