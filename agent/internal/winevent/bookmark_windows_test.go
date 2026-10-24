//go:build windows

package winevent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Native tests use a classic event log created for the test and removed
// afterwards; they never clear Security, System or another channel. They need
// Administrator: run with SIEM_NATIVE_EVENTLOG=1 (CI's Windows runner does).

func powershell(t *testing.T, format string, args ...any) {
	t.Helper()
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf(format, args...))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("powershell %q: %v\n%s", fmt.Sprintf(format, args...), err, out)
	}
}

// testChannel creates a disposable classic log (only the first 8 characters
// of a log name are significant, so the name is 8 long and random).
func testChannel(t *testing.T) string {
	t.Helper()
	if os.Getenv("SIEM_NATIVE_EVENTLOG") == "" {
		t.Skip("native event log test: set SIEM_NATIVE_EVENTLOG=1 and run as Administrator")
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	name := "SIEM" + hex.EncodeToString(b[:])
	powershell(t, "New-EventLog -LogName %s -Source %s", name, name)
	t.Cleanup(func() {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("Remove-EventLog -LogName %s", name))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("removing test log %s: %v\n%s", name, err, out)
		}
	})
	// A new classic log can be queried before it can be subscribed to: wait
	// until a subscription stays open (the durable tailer retries instead).
	waitNative(t, "channel "+name, func() bool {
		if _, err := Baseline(context.Background(), name); err != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		err := SubscribeResume(ctx, name, Resume{Empty: true, Initialized: true}, func(Event) error { return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("channel %s not subscribable yet: %v", name, err)
			return false
		}
		return true
	})
	return name
}

// await waits for marker, failing at once (with what arrived) when the
// subscription ended early, instead of timing out blind.
func (n *nativeRun) await(t *testing.T, marker string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for n.count(marker) == 0 {
		select {
		case err := <-n.done:
			t.Fatalf("subscription ended before %s: %v; events: %s", marker, err, n.describe())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; events: %s", marker, n.describe())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (n *nativeRun) describe() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var parts []string
	for _, ev := range n.events {
		line := ev.Line
		if len(line) > 160 {
			line = line[:160]
		}
		parts = append(parts, fmt.Sprintf("{record=%d err=%v line=%q}", ev.RecordID, ev.Err, line))
	}
	return fmt.Sprintf("%d %v", len(parts), parts)
}

func writeMarker(t *testing.T, channel string) string {
	t.Helper()
	marker := fmt.Sprintf("marker-%d", time.Now().UnixNano())
	powershell(t, "Write-EventLog -LogName %s -Source %s -EventId 701 -EntryType Information -Message '%s'", channel, channel, marker)
	return marker
}

func waitNative(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// subscription runs SubscribeResume in the background and records events.
type nativeRun struct {
	mu     sync.Mutex
	events []Event
	cancel context.CancelFunc
	done   chan error
}

func startResume(channel string, r Resume) *nativeRun {
	ctx, cancel := context.WithCancel(context.Background())
	n := &nativeRun{cancel: cancel, done: make(chan error, 1)}
	go func() {
		n.done <- SubscribeResume(ctx, channel, r, func(ev Event) error {
			n.mu.Lock()
			n.events = append(n.events, ev)
			n.mu.Unlock()
			return nil
		})
	}()
	return n
}

func (n *nativeRun) count(marker string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, ev := range n.events {
		if strings.Contains(ev.Line, marker) {
			c++
		}
	}
	return c
}

func (n *nativeRun) last() Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.events[len(n.events)-1]
}

func (n *nativeRun) stop(t *testing.T) error {
	t.Helper()
	n.cancel()
	select {
	case err := <-n.done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("SubscribeResume did not stop")
		return nil
	}
}

func TestNativeResumeAfterBookmarkExactlyOnce(t *testing.T) {
	channel := testChannel(t)
	base, err := Baseline(context.Background(), channel)
	if err != nil || !base.Initialized {
		t.Fatalf("baseline %+v %v", base, err)
	}

	first := startResume(channel, base)
	a := writeMarker(t, channel)
	first.await(t, a)
	if err := first.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: %v", err)
	}
	bookmark := first.last().Bookmark
	if !strings.Contains(bookmark, "BookmarkList") || first.last().RecordID == 0 || first.last().Err != nil {
		t.Fatalf("event %+v", first.last())
	}

	b := writeMarker(t, channel) // while "the agent" is down
	second := startResume(channel, Resume{Bookmark: bookmark, Initialized: true})
	second.await(t, b)
	time.Sleep(time.Second)
	if err := second.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: %v", err)
	}
	if second.count(a) != 0 || second.count(b) != 1 {
		t.Fatalf("resume after the bookmark replayed or duplicated: A=%d B=%d", second.count(a), second.count(b))
	}

	again, err := Baseline(context.Background(), channel)
	if err != nil || again.Empty || again.Bookmark == "" {
		t.Fatalf("baseline of a non-empty channel %+v %v", again, err)
	}
}

func TestNativeClearedChannelIsAGap(t *testing.T) {
	channel := testChannel(t)
	base, err := Baseline(context.Background(), channel)
	if err != nil {
		t.Fatal(err)
	}
	run := startResume(channel, base)
	a := writeMarker(t, channel)
	run.await(t, a)
	run.stop(t)
	bookmark := run.last().Bookmark

	powershell(t, "Clear-EventLog -LogName %s", channel) // only the test's own log
	c := writeMarker(t, channel)
	stale := startResume(channel, Resume{Bookmark: bookmark, Initialized: true})
	var gapErr error
	select {
	case gapErr = <-stale.done:
	case <-time.After(10 * time.Second):
		stale.cancel()
		<-stale.done
		t.Fatalf("a bookmark into a cleared log did not fail; events seen: %d", stale.count(c))
	}
	if !errors.Is(gapErr, ErrBookmarkGap) {
		t.Fatalf("cleared log: want ErrBookmarkGap, got %v", gapErr)
	}

	recovered := startResume(channel, Resume{Empty: true, Initialized: true})
	recovered.await(t, c)
	recovered.stop(t)
}
