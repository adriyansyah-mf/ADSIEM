package tailer

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/winevent"
)

const testChannelPath = EventLogPrefix + "SIEMTest"

// fakeChannel scripts winevent: a retained record list, bookmarks "bm:<n>".
type fakeChannel struct {
	mu       sync.Mutex
	records  []int
	resumes  []winevent.Resume
	failures []error // returned by the next subscriptions, in order
	bad      map[int]bool
	cleared  bool // bookmarks before this are gone
}

func (c *fakeChannel) baseline(ctx context.Context, channel string) (winevent.Resume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.records) == 0 {
		return winevent.Resume{Empty: true, Initialized: true}, nil
	}
	return winevent.Resume{Bookmark: fmt.Sprintf("bm:%d", c.records[len(c.records)-1]), Initialized: true}, nil
}

// subscribe delivers what is new as one batch per poll, like one EvtNext.
func (c *fakeChannel) subscribe(ctx context.Context, channel string, resume winevent.Resume, emit func([]winevent.Event) error) error {
	c.mu.Lock()
	c.resumes = append(c.resumes, resume)
	if len(c.failures) > 0 {
		err := c.failures[0]
		c.failures = c.failures[1:]
		c.mu.Unlock()
		return err
	}
	after := -1
	if resume.Bookmark != "" {
		fmt.Sscanf(resume.Bookmark, "bm:%d", &after)
		if c.cleared {
			c.mu.Unlock()
			return fmt.Errorf("%w: test channel cleared", winevent.ErrBookmarkGap)
		}
	}
	c.mu.Unlock()
	sent := map[int]bool{}
	for {
		c.mu.Lock()
		var pending []int
		for _, r := range c.records {
			if r > after && !sent[r] {
				pending = append(pending, r)
			}
		}
		bad := c.bad
		c.mu.Unlock()
		var batch []winevent.Event
		for _, r := range pending {
			ev := winevent.Event{Line: fmt.Sprintf("EventID=701 Record=%d", r), Bookmark: fmt.Sprintf("bm:%d", r), RecordID: uint64(r)}
			if bad[r] {
				ev.Line, ev.Err = "", errors.New("render failed")
			}
			batch = append(batch, ev)
		}
		if len(batch) > 0 {
			if err := emit(batch); err != nil {
				return err
			}
			for _, r := range pending {
				sent[r] = true
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (c *fakeChannel) write(records ...int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, records...)
}

func useFakeChannel(t *testing.T, c *fakeChannel) {
	t.Helper()
	sub, base, wait := subscribeEventLog, baselineEventLog, eventLogRetryMin
	subscribeEventLog, baselineEventLog, eventLogRetryMin = c.subscribe, c.baseline, 10*time.Millisecond
	t.Cleanup(func() { subscribeEventLog, baselineEventLog, eventLogRetryMin = sub, base, wait })
}

type runningLog struct {
	cancel context.CancelFunc
	done   chan error
	cap    *capture
}

func (e *tailEnv) tailLog(fail func(int, evidence.Draft) error) *runningLog {
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningLog{cancel: cancel, done: make(chan error, 1), cap: &capture{sink: e.publisher, fail: fail}}
	go func() { r.done <- TailEventLogDurable(ctx, testChannelPath, "windows_security", e.journal, r.cap) }()
	return r
}

func (r *runningLog) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("TailEventLogDurable: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TailEventLogDurable did not stop")
	}
}

func TestDurableEventLogBaselinesThenResumesExactlyOnce(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{records: []int{1, 2, 3}} // history before enablement
	useFakeChannel(t, ch)
	r := env.tailLog(nil)
	waitFor(t, "baseline", func() bool { _, ok := env.journal.Cursor(testChannelPath); return ok })
	ch.write(4, 5)
	waitFor(t, "events 4 and 5", func() bool { return len(r.cap.lines()) == 2 })
	r.stop(t)
	if got := r.cap.lines(); got[0] != "EventID=701 Record=4" || got[1] != "EventID=701 Record=5" {
		t.Fatalf("history replayed or events missed: %v", got)
	}
	c := r.cap.snapshot()[1].Cursor
	if c.Source != testChannelPath || c.Identity != "SIEMTest" || c.Bookmark != "bm:5" || c.Generation == "" {
		t.Fatalf("cursor %+v", c)
	}
	if first := ch.resumes[0]; first.Bookmark != "bm:3" || !first.Initialized {
		t.Fatalf("first subscription did not start after the baseline: %+v", first)
	}

	ch.write(6) // while the agent is down
	env.restart()
	r = env.tailLog(nil)
	waitFor(t, "event 6", func() bool { return len(r.cap.lines()) == 1 })
	time.Sleep(50 * time.Millisecond)
	r.stop(t)
	if got := r.cap.lines(); len(got) != 1 || got[0] != "EventID=701 Record=6" {
		t.Fatalf("after restart: %v", got)
	}
	if last := ch.resumes[len(ch.resumes)-1]; last.Bookmark != "bm:5" {
		t.Fatalf("resumed from %+v, not the committed bookmark", last)
	}
}

func TestDurableEventLogEmptyChannelRecoversDowntimeEvents(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{}
	useFakeChannel(t, ch)
	r := env.tailLog(nil)
	waitFor(t, "empty baseline", func() bool { c, ok := env.journal.Cursor(testChannelPath); return ok && c.Empty })
	r.stop(t)
	ch.write(1, 2) // created while the agent was down
	env.restart()
	r = env.tailLog(nil)
	waitFor(t, "downtime events", func() bool { return len(r.cap.lines()) == 2 })
	r.stop(t)
	if last := ch.resumes[len(ch.resumes)-1]; !last.Empty || last.Bookmark != "" {
		t.Fatalf("empty baseline must resume from the oldest event: %+v", last)
	}
}

func TestDurableEventLogAdmissionFailureKeepsTheCommittedBookmark(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{}
	useFakeChannel(t, ch)
	r := env.tailLog(func(try int, d evidence.Draft) error {
		if d.Cursor.Bookmark == "bm:2" {
			return evidence.ErrFull
		}
		return nil
	})
	waitFor(t, "baseline", func() bool { _, ok := env.journal.Cursor(testChannelPath); return ok })
	ch.write(1, 2)
	waitFor(t, "paused source", func() bool { return env.journal.Snapshot().Sources[testChannelPath].State == "paused" })
	r.stop(t)
	c, _ := env.journal.Cursor(testChannelPath)
	if c.Bookmark != "bm:1" {
		t.Fatalf("bookmark moved past an unadmitted event: %+v", c)
	}
	env.restart()
	r = env.tailLog(nil)
	waitFor(t, "retried event", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	if got := r.cap.lines()[0]; got != "EventID=701 Record=2" {
		t.Fatalf("got %q", got)
	}
}

func TestDurableEventLogClearedChannelIsAGapAndANewGeneration(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{}
	useFakeChannel(t, ch)
	r := env.tailLog(nil)
	waitFor(t, "baseline", func() bool { _, ok := env.journal.Cursor(testChannelPath); return ok })
	ch.write(1)
	waitFor(t, "event 1", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	before, _ := env.journal.Cursor(testChannelPath)

	ch.mu.Lock() // cleared, then new events
	ch.records, ch.cleared = []int{1, 2}, true
	ch.mu.Unlock()
	env.restart()
	r = env.tailLog(nil)
	waitFor(t, "recovered events", func() bool { return len(r.cap.lines()) == 2 })
	r.stop(t)
	if gaps := env.journal.Snapshot().UnknownGaps; gaps != 1 {
		t.Fatalf("unknown gaps %d", gaps)
	}
	recovered := r.cap.snapshot()[0].Cursor
	if recovered.Generation == before.Generation {
		t.Fatal("recovery kept the old generation")
	}
	if last := ch.resumes[len(ch.resumes)-1]; !last.Empty {
		t.Fatalf("recovery must start at the oldest retained event: %+v", last)
	}
}

func TestDurableEventLogUnrenderableEventIsCountedNotSkippedSilently(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{bad: map[int]bool{1: true}}
	useFakeChannel(t, ch)
	r := env.tailLog(nil)
	waitFor(t, "baseline", func() bool { _, ok := env.journal.Cursor(testChannelPath); return ok })
	ch.write(1, 2)
	waitFor(t, "good event", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	h := env.journal.Snapshot()
	if h.KnownLoss["source_failure"] != 1 || h.Sources[testChannelPath].State != "degraded" {
		t.Fatalf("render failure not visible: %+v", h)
	}
}

func TestDurableEventLogSubscribeErrorsRetryAndShowUnavailable(t *testing.T) {
	env := newTailEnv(t)
	ch := &fakeChannel{failures: []error{errors.New("access denied"), errors.New("access denied")}}
	useFakeChannel(t, ch)
	r := env.tailLog(nil)
	waitFor(t, "unavailable", func() bool { return env.journal.Snapshot().Sources[testChannelPath].State == "unavailable" })
	ch.write(1)
	waitFor(t, "event after recovery", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
}

func TestDurableEventLogUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("real Windows event log")
	}
	env := newTailEnv(t) // real winevent: unsupported here
	r := env.tailLog(nil)
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unsupported source did not return")
	}
	if s := env.journal.Snapshot().Sources[testChannelPath]; s.State != "unavailable" || s.Reason != "unsupported" {
		t.Fatalf("health %+v", s)
	}
}
