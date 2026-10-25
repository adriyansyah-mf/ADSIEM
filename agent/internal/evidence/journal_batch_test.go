package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func batchEvents(t *testing.T, o Options, n int) []Envelope {
	t.Helper()
	events := make([]Envelope, n)
	for i := range events {
		e, err := NewEnvelope(o.AgentID, "host", Draft{LogType: "syslog", RawMessage: fmt.Sprintf("line %d %s", i, strings.Repeat("x", 200)),
			Cursor: &Cursor{Source: "file:/var/log/app.log", Generation: "g", Identity: "1:2", Offset: int64(i + 1)}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		events[i] = e
	}
	return events
}

// retainedIDs reopens the journal and returns its undelivered events in order.
func retainedIDs(t *testing.T, o Options) []string {
	t.Helper()
	j := openJournal(t, o)
	defer j.Close()
	var ids []string
	err := j.walkEvents(context.Background(), func(e Envelope, _ eventPosition) (bool, error) {
		ids = append(ids, e.EventID)
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func eventIDs(events []Envelope) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.EventID
	}
	return out
}

func TestAppendBatchAdmitsEverythingAcrossSegmentsAndSurvivesReopen(t *testing.T) {
	o := journalOptions(t) // 64 KiB segments: 400 events of ~300 bytes need several
	j := openJournal(t, o)
	events := batchEvents(t, o, 400)
	n, err := j.AppendBatch(context.Background(), events)
	if err != nil || n != len(events) {
		t.Fatalf("admitted %d: %v", n, err)
	}
	if len(j.segments) < 2 {
		t.Fatalf("the batch did not cross a segment: %d segment(s)", len(j.segments))
	}
	if c, _ := j.Cursor("file:/var/log/app.log"); c.Offset != 400 {
		t.Fatalf("cursor after the batch %+v", c)
	}
	if got := j.positions(events[399].EventID); len(got) != 1 {
		t.Fatalf("last event not indexed: %v", got)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	got := retainedIDs(t, o)
	if fmt.Sprint(got) != fmt.Sprint(eventIDs(events)) {
		t.Fatal("events after reopen differ from the admitted batch")
	}
}

func TestAppendBatchStopsAtTheFirstEventItCannotAdmit(t *testing.T) {
	for name, tc := range map[string]struct {
		breakAt func(t *testing.T, o Options, events []Envelope)
		want    error
	}{
		"oversized": {func(t *testing.T, o Options, events []Envelope) {
			events[3].RawMessage = strings.Repeat("y", o.MaxEventBytes+1)
		}, ErrOversize},
		"another agent's event": {func(t *testing.T, o Options, events []Envelope) {
			events[3].AgentID = "22222222-2222-4222-8222-222222222222"
		}, ErrIdentityMismatch},
		"same id, different content": {func(t *testing.T, o Options, events []Envelope) {
			events[3].EventID = events[1].EventID
		}, ErrConflict},
	} {
		t.Run(name, func(t *testing.T) {
			o := journalOptions(t)
			j := openJournal(t, o)
			events := batchEvents(t, o, 6)
			tc.breakAt(t, o, events)
			n, err := j.AppendBatch(context.Background(), events)
			if n != 3 || !errors.Is(err, tc.want) {
				t.Fatalf("admitted %d, err %v; want 3, %v", n, err, tc.want)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if got := retainedIDs(t, o); fmt.Sprint(got) != fmt.Sprint(eventIDs(events[:3])) {
				t.Fatalf("retained %v, want the 3 admitted", got)
			}
		})
	}
}

func TestAppendBatchAdmitsWhatFitsAndReportsAFullJournal(t *testing.T) {
	o := journalOptions(t)
	o.MaxBytes, o.ReservedBytes, o.SegmentBytes = 64<<10, 16<<10, 16<<10 // ~48 KiB for events
	j := openJournal(t, o)
	events := batchEvents(t, o, 400)
	n, err := j.AppendBatch(context.Background(), events)
	if !errors.Is(err, ErrFull) || n == 0 || n >= len(events) {
		t.Fatalf("admitted %d: %v", n, err)
	}
	if h := j.Snapshot(); h.Reason != "capacity" {
		t.Fatalf("a full journal is not reported: %+v", h)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if got := retainedIDs(t, o); fmt.Sprint(got) != fmt.Sprint(eventIDs(events[:n])) {
		t.Fatalf("retained %d events, want the %d admitted", len(got), n)
	}
}

func TestAppendBatchAllowsAnIdenticalRepeat(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	events := batchEvents(t, o, 3)
	n, err := j.AppendBatch(context.Background(), []Envelope{events[0], events[1], events[0], events[2]})
	if n != 4 || err != nil {
		t.Fatalf("admitted %d: %v", n, err)
	}
	if got := j.positions(events[0].EventID); len(got) != 2 {
		t.Fatalf("occurrences %v", got)
	}
}

// BenchmarkAppendBatch is one group commit of 100 events: the per-event cost
// to compare with BenchmarkAppendSync (one flush per event).
func BenchmarkAppendBatch(b *testing.B) {
	o := benchOptions(b)
	j, err := Open(o)
	if err != nil {
		b.Fatal(err)
	}
	defer j.Close()
	const size = 100
	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		events := make([]Envelope, size)
		for k := range events {
			events[k] = benchEvent(b, o, i*size+k)
		}
		b.StartTimer()
		if n, err := j.AppendBatch(context.Background(), events); err != nil || n != size {
			b.Fatalf("admitted %d: %v", n, err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N*size), "µs/event")
}
