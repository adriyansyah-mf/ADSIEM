//go:build windows

package tailer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/winevent"
)

// The evidence-resume harness (tests/windows/evidence-resume.ps1): a real
// journal and a disposable classic event log; stop the collector, write a
// marker, resume from the same journal directory, every marker exactly once.

func ps(t *testing.T, format string, args ...any) {
	t.Helper()
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(format, args...)).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell: %v\n%s", err, out)
	}
}

func TestNativeDurableEventLogResumeExactlyOnce(t *testing.T) {
	if os.Getenv("SIEM_NATIVE_EVENTLOG") == "" {
		t.Skip("native event log test: set SIEM_NATIVE_EVENTLOG=1 and run as Administrator")
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	channel := "SIEM" + hex.EncodeToString(b[:])
	ps(t, "New-EventLog -LogName %s -Source %s", channel, channel)
	defer exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Remove-EventLog -LogName "+channel).Run()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := winevent.Baseline(context.Background(), channel); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("test channel never became readable")
		}
		time.Sleep(100 * time.Millisecond)
	}
	path := EventLogPrefix + channel
	write := func() string {
		m := fmt.Sprintf("marker-%d", time.Now().UnixNano())
		ps(t, "Write-EventLog -LogName %s -Source %s -EventId 701 -EntryType Information -Message '%s'", channel, channel, m)
		return m
	}

	env := newTailEnv(t)
	start := func() *runningLog {
		ctx, cancel := context.WithCancel(context.Background())
		r := &runningLog{cancel: cancel, done: make(chan error, 1), cap: &capture{sink: env.publisher}}
		go func() { r.done <- TailEventLogDurable(ctx, path, "windows_application", env.journal, r.cap) }()
		return r
	}
	count := func(r *runningLog, marker string) int {
		n := 0
		for _, l := range r.cap.lines() {
			if strings.Contains(l, marker) {
				n++
			}
		}
		return n
	}
	wait := func(what string, cond func() bool) {
		deadline := time.Now().Add(30 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	r := start()
	wait("baseline", func() bool { _, ok := env.journal.Cursor(path); return ok })
	a := write()
	wait("marker A", func() bool { return count(r, a) == 1 })
	r.stop(t)

	mb := write() // the agent is down
	env.restart()
	r = start()
	wait("marker B", func() bool { return count(r, mb) == 1 })
	time.Sleep(time.Second)
	r.stop(t)
	if count(r, a) != 0 || count(r, mb) != 1 {
		t.Fatalf("after restart A=%d B=%d, want 0 and 1", count(r, a), count(r, mb))
	}
	if c, _ := env.journal.Cursor(path); !strings.Contains(c.Bookmark, "BookmarkList") {
		t.Fatalf("cursor %+v", c)
	}

	// clearing the test's own log loses the bookmark: a gap, then recovery
	ps(t, "Clear-EventLog -LogName %s", channel)
	c := write()
	env.restart()
	r = start()
	wait("marker C after the gap", func() bool { return count(r, c) == 1 })
	r.stop(t)
	if gaps := env.journal.Snapshot().UnknownGaps; gaps != 1 {
		t.Fatalf("unknown gaps %d, want 1", gaps)
	}
}
