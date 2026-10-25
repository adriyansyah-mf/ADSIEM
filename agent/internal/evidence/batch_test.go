package evidence

import (
	"context"
	"errors"
	"testing"
	"time"
)

func appendN(t *testing.T, j *Journal, n int) []Envelope {
	t.Helper()
	var out []Envelope
	for i := 0; i < n; i++ {
		e := journalEvent(t, j.options)
		if err := j.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestPeekBatchReturnsDeliverableEventsInOrderWithinBounds(t *testing.T) {
	j := openJournal(t, journalOptions(t))
	events := appendN(t, j, 6)
	ctx := context.Background()
	if err := j.Quarantine(ctx, events[1].EventID, "rejected_status_422"); err != nil {
		t.Fatal(err)
	}
	got, err := j.PeekBatch(ctx, 3, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].EventID != events[0].EventID || got[1].EventID != events[2].EventID || got[2].EventID != events[3].EventID {
		t.Fatalf("batch %v", ids(got))
	}
	// the byte bound always admits at least one event
	if got, _ := j.PeekBatch(ctx, 10, 1); len(got) != 1 {
		t.Fatalf("byte-bounded batch has %d events", len(got))
	}
	// peeking does not consume
	if again, _ := j.PeekBatch(ctx, 3, 1<<20); ids(again)[0] != events[0].EventID {
		t.Fatal("peek consumed events")
	}
}

func ids(es []Envelope) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.EventID)
	}
	return out
}

func TestAckBatchIsOneCheckpointAndKeepsAckChecks(t *testing.T) {
	j := openJournal(t, journalOptions(t))
	events := appendN(t, j, 5)
	ctx := context.Background()
	generation := j.checkpoint.Generation
	if err := j.MarkAttempts(ctx, ids(events[:4]), time.Now()); err != nil {
		t.Fatal(err)
	}
	var receipts []Receipt
	for _, e := range events[:4] {
		receipts = append(receipts, Receipt{EventID: e.EventID, ReceiptID: testReceipt})
	}
	if err := j.AckBatch(ctx, receipts); err != nil {
		t.Fatal(err)
	}
	if got := j.checkpoint.Generation - generation; got != 2 {
		t.Fatalf("published %d checkpoints for one attempt batch and one ack batch", got)
	}
	left, _ := j.PeekBatch(ctx, 10, 1<<20)
	if len(left) != 1 || left[0].EventID != events[4].EventID {
		t.Fatalf("left %v", ids(left))
	}
	if j.Snapshot().LastReceiptAt == nil {
		t.Fatal("receipt time not recorded")
	}
	// a bad item refuses the whole batch and publishes nothing
	generation = j.checkpoint.Generation
	if err := j.AckBatch(ctx, []Receipt{{EventID: events[4].EventID, ReceiptID: testReceipt}, {EventID: "nope", ReceiptID: testReceipt}}); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("unknown event: %v", err)
	}
	if err := j.AckBatch(ctx, []Receipt{{EventID: events[4].EventID, ReceiptID: "not-a-uuid"}}); err == nil {
		t.Fatal("invalid receipt accepted")
	}
	if j.checkpoint.Generation != generation {
		t.Fatal("a refused batch published a checkpoint")
	}
	if err := j.Quarantine(ctx, events[4].EventID, "rejected_status_400"); err != nil {
		t.Fatal(err)
	}
	if err := j.AckBatch(ctx, []Receipt{{EventID: events[4].EventID, ReceiptID: testReceipt}}); !errors.Is(err, ErrTerminal) {
		t.Fatalf("quarantined event acked: %v", err)
	}
}

func TestMarkAttemptsKeepsFirstAttemptsAndCountsRetries(t *testing.T) {
	j := openJournal(t, journalOptions(t))
	events := appendN(t, j, 3)
	ctx := context.Background()
	first := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := j.MarkAttempts(ctx, ids(events), first); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkAttempts(ctx, ids(events[:2]), first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		at, ok, err := j.FirstAttempt(ctx, e.EventID)
		if err != nil || !ok || !at.Equal(first) {
			t.Fatalf("first attempt %v %v %v", at, ok, err)
		}
	}
	if got := j.Snapshot().Retries; got != 2 {
		t.Fatalf("retries %d", got)
	}
	if err := j.MarkAttempts(ctx, []string{"nope"}, first); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("unknown: %v", err)
	}
}
