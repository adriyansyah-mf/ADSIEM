package evidence

import (
	"context"
	"testing"
	"time"
)

// Snapshot counts from the index; OldestQueuedAt must still be the exact
// earliest collection time among undelivered records, whatever the append
// order, and survive a reopen (the index is rebuilt from disk).
func TestSnapshotOldestQueuedIsExactAndSkipsDelivered(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	base := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	at := func(d time.Duration) Envelope {
		e, err := NewEnvelope(o.AgentID, "host", Draft{LogType: "syslog", RawMessage: d.String()}, base.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	at(5 * time.Second)
	at(900 * time.Millisecond) // same second as the next, but later
	want := at(300 * time.Millisecond)
	oldest := at(-time.Hour) // appended last, collected first: a legacy import
	if err := j.Ack(context.Background(), oldest.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}

	h := j.Snapshot()
	if h.QueuedEvents != 3 || h.IndexedEvents != 4 || h.OldestQueuedAt == nil || !h.OldestQueuedAt.Equal(want.CollectedAt) {
		t.Fatalf("snapshot %+v oldest %v, want %v", h, h.OldestQueuedAt, want.CollectedAt)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openJournal(t, o)
	if again := reopened.Snapshot(); again.QueuedEvents != 3 || !again.OldestQueuedAt.Equal(want.CollectedAt) {
		t.Fatalf("after reopen %+v", again)
	}
}
