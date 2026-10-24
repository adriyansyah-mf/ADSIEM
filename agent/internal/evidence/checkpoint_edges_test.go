package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAckAllIdenticalOccurrencesAndRejectConflictingIdentity(t *testing.T) {
	// Given two retry copies of one immutable event and a conflicting candidate.
	j := openJournal(t, journalOptions(t))
	e := appendEvidence(t, j)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	conflict := e
	conflict.RawMessage = "conflict"
	if err := j.Append(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused ID payload: %v", err)
	}
	// When one receipt covers that identity, both physical copies stop replaying.
	if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("duplicate ACK loop: %v %v", ok, err)
	}
}

func TestAttemptAndTerminalStateCannotBeBypassedByDuplicateAppend(t *testing.T) {
	for _, state := range []string{"attempt", "held", "quarantined"} {
		t.Run(state, func(t *testing.T) {
			// Given persisted attempt/terminal metadata for one retained ID.
			o := journalOptions(t)
			j := openJournal(t, o)
			e := appendEvidence(t, j)
			var err error
			switch state {
			case "attempt":
				err = j.MarkAttempt(context.Background(), e.EventID, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			case "held":
				err = j.Hold(context.Background(), e.EventID, "operator")
			case "quarantined":
				err = j.Quarantine(context.Background(), e.EventID, "invalid")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Compact(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			j = openJournal(t, o)
			// When an old immutable envelope is re-admitted, reject the bypass.
			if err := j.Append(context.Background(), e); !errors.Is(err, ErrConflict) {
				t.Fatalf("duplicate %s: %v", state, err)
			}
		})
	}
}

func TestCompactFullControlRefusalLeavesWriterUsable(t *testing.T) {
	// Given no reserved allowance for an initial checkpoint.
	o := journalOptions(t)
	o.ReservedBytes = 0
	j := openJournal(t, o)
	appendEvidence(t, j)
	// When compaction cannot publish, its quota rejection performs no mutation.
	if err := j.Compact(context.Background()); !errors.Is(err, ErrFull) {
		t.Fatalf("control budget: %v", err)
	}
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatalf("capacity rejection poisoned healthy writer: %v", err)
	}
}

func TestCompactPartialSegmentBoundsControlMetadata(t *testing.T) {
	// Given many tiny events in one segment and a comparatively small reserve.
	o := journalOptions(t)
	o.MaxBytes = 65536
	o.SegmentBytes = 32768
	o.ReservedBytes = 4096
	o.MaxEventBytes = 2048
	j := openJournal(t, o)
	var events []Envelope
	for range 50 {
		events = append(events, appendEvidence(t, j))
	}
	first := events[0]
	if err := j.Hold(context.Background(), first.EventID, "operator"); err != nil {
		t.Fatal(err)
	}
	// When receipt IDs are individually large, merged spans still fit reserve.
	for _, e := range events[1:] {
		if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(j.segments) != 1 || j.Snapshot().QueuedEvents != 1 {
		t.Fatal("partial segment accounting lost held evidence")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	if h := j.Snapshot(); h.Held != 1 || h.QueuedEvents != 1 {
		t.Fatalf("partial restart: %#v", h)
	}
}

func TestCompactRetainedCursorDoesNotRegressAndNewTailAdvances(t *testing.T) {
	// Given a retained old event and a later baseline checkpoint.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := appendEvidence(t, j)
	if err := j.Hold(context.Background(), e.EventID, "operator"); err != nil {
		t.Fatal(err)
	}
	c := *e.Cursor
	c.Offset = 100
	if err := j.SaveBaseline(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A newer append after checkpoint must win over its captured cursor.
	next := journalEvent(t, o)
	next.Cursor.Offset = 200
	if err := j.Append(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	if got, ok := j.Cursor("syslog"); !ok || got.Offset != 200 {
		t.Fatalf("cursor replay after checkpoint: %#v %v", got, ok)
	}
}

func TestCompactNeverDeletesForensicCopies(t *testing.T) {
	// Given a genuine torn-tail forensic copy from restart repair.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := appendEvidence(t, j)
	name := j.segments[0].name
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(o.Dir, name), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("EVJR")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	// When the delivered segment is reclaimed, forensic bytes remain accounted.
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	names, err := j.dir.names()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, name := range names {
		if strings.HasPrefix(name, "torn-") {
			found = true
		}
	}
	if !found {
		t.Fatal("compaction removed forensic bytes")
	}
}

func TestHealthInvalidControlsAndOverflowAreRejected(t *testing.T) {
	// Given bounded source/reason fields and cumulative counters.
	j := openJournal(t, journalOptions(t))
	for _, reason := range []string{"freeform secret", strings.Repeat("x", 257)} {
		if err := j.RecordLoss(context.Background(), "source", reason, 1, false); !errors.Is(err, ErrInvalidControl) {
			t.Fatalf("unbounded reason: %v", err)
		}
	}
	if err := j.RecordLoss(context.Background(), "source", "capacity", maxCounter, false); err != nil {
		t.Fatal(err)
	}
	// When incrementing beyond the counter range, reject before publication.
	if err := j.RecordLoss(context.Background(), "source", "capacity", 1, false); !errors.Is(err, ErrInvalidControl) {
		t.Fatalf("overflow: %v", err)
	}
	if got := j.Snapshot().KnownLoss["capacity"]; got != maxCounter {
		t.Fatalf("counter overflowed: %d", got)
	}
}
