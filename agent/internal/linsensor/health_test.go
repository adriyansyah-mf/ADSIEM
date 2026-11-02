package linsensor

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanaryReportsOnlyChanges(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHealthChecker("/var/tmp/.siem-sensor-canary-7")
	h.now = func() time.Time { return now }

	// Seen: nothing to report.
	h.start()
	h.claim(h.canaryPath)
	now = now.Add(canaryWait)
	if v := h.verdict(); v != "" {
		t.Fatalf("seen canary reported %q", v)
	}
	// Not seen: blind, once.
	h.start()
	if v := h.verdict(); v != "" {
		t.Fatalf("judged before canaryWait: %q", v)
	}
	now = now.Add(canaryWait)
	v := h.verdict()
	if !strings.HasPrefix(v, "event=sensor_blind check=canary waited_seconds=15 last_seen=1970-01-01T00:16:40Z") {
		t.Fatalf("blind = %q", v)
	}
	h.start()
	now = now.Add(canaryWait)
	if v := h.verdict(); v != "" {
		t.Fatalf("still blind reported again: %q", v)
	}
	// Seen again: recovered.
	h.start()
	h.claim(h.canaryPath)
	now = now.Add(canaryWait)
	if v := h.verdict(); !strings.HasPrefix(v, "event=sensor_recovered") {
		t.Fatalf("recovered = %q", v)
	}
	// An aborted canary (no shell) is never judged.
	h.start()
	h.abort()
	now = now.Add(canaryWait)
	if v := h.verdict(); v != "" {
		t.Fatalf("aborted canary judged: %q", v)
	}
}

func TestCanaryEventsAreNotShipped(t *testing.T) {
	var lines []string
	p := newProcessor(func(_, l string) { lines = append(lines, l) }, nil, map[string]bool{}, fakeProc{})
	h := newHealthChecker("/var/tmp/.siem-sensor-canary-7")
	p.canary = h.claim
	h.start()
	p.handle(rawEvent{kind: kindOpen, arg0: oCreat, tgid: 50, comm: "sh", path: h.canaryPath})
	p.handle(rawEvent{kind: kindUnlink, tgid: 51, comm: "rm", path: h.canaryPath})
	p.handle(rawEvent{kind: kindOpen, arg0: oCreat, tgid: 52, comm: "sh", path: "/var/tmp/other"})
	if len(lines) != 1 || !strings.Contains(lines[0], "/var/tmp/other") {
		t.Fatalf("lines = %q", lines)
	}
	if !h.seen {
		t.Fatal("canary not recorded as seen")
	}
}

func TestSelfLine(t *testing.T) {
	if l := selfLine(10, 99, true, nil); l != "event=self_map_overwritten expected_tgid=10 found_tgid=99 restored=true" {
		t.Fatal(l)
	}
	if l := selfLine(10, 0, false, errors.New("no map")); !strings.HasSuffix(l, `restored=false error="no map"`) {
		t.Fatal(l)
	}
}
