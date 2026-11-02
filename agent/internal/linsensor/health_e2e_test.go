//go:build linux

package linsensor

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// The sensor's tamper checks against the real kernel (LINSENSOR_E2E=1, root):
// an overwritten self map is restored and reported; a canary is seen while the
// programs are attached and missed once they are detached, as
// `bpftool link detach` would.
func TestSensorHealthEndToEnd(t *testing.T) {
	if os.Getenv("LINSENSOR_E2E") != "1" {
		t.Skip("set LINSENSOR_E2E=1 (needs root, BTF and tracefs)")
	}
	var c collected
	s, err := Start(Options{Push: c.push})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if s.health == nil {
		t.Fatal("no health checker with file events on")
	}

	// 1. self map overwritten with another tgid: restored and reported.
	if err := s.coll.Maps["self"].Update(uint32(0), uint32(12345), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	s.checkSelf()
	c.wait(t, LogHealth, "event=self_map_overwritten", "found_tgid=12345", "restored=true")
	var tgid uint32
	if err := s.coll.Maps["self"].Lookup(uint32(0), &tgid); err != nil || tgid != s.self {
		t.Fatalf("self map = %d (%v), want %d", tgid, err, s.self)
	}
	s.checkSelf() // intact now: no second line
	c.mu.Lock()
	n := strings.Count(strings.Join(c.lines, "\n"), "self_map_overwritten")
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d self_map_overwritten lines", n)
	}

	seen := func(wait time.Duration) bool {
		for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			s.mu.Lock()
			ok := s.health.seen
			s.mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	judge := func() string { // as if canaryWait had passed
		s.mu.Lock()
		defer s.mu.Unlock()
		s.health.started = s.health.started.Add(-canaryWait)
		return s.health.verdict()
	}

	// 2. attached: the canary is seen, nothing reported.
	s.runCanary()
	if !seen(5 * time.Second) {
		t.Fatal("canary not seen with the programs attached")
	}
	if v := judge(); v != "" {
		t.Fatalf("healthy sensor reported %q", v)
	}

	// 3. programs detached: the canary is missed, the sensor is blind.
	for _, l := range s.links {
		l.Close()
	}
	s.links = nil
	s.runCanary()
	if seen(3 * time.Second) {
		t.Fatal("canary seen with every program detached")
	}
	if v := judge(); !strings.HasPrefix(v, "event=sensor_blind check=canary") {
		t.Fatalf("detached sensor verdict = %q", v)
	}
	// the canary's own file events were never shipped
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		if strings.Contains(l, LogFile) && strings.Contains(l, "siem-sensor-canary") {
			t.Fatalf("canary event shipped: %s", l)
		}
	}
}
