package evidence

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

const testReceipt = "22222222-2222-4222-8222-222222222222"

func appendEvidence(t *testing.T, j *Journal) Envelope {
	t.Helper()
	e := journalEvent(t, j.options)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAckUnknownEventIsRejected(t *testing.T) {
	// Given an empty journal; when an unrelated receipt arrives, reject it.
	j := openJournal(t, journalOptions(t))
	if err := j.Ack(context.Background(), "missing", testReceipt); err == nil {
		t.Fatal("accepted unknown event ACK")
	}
}

func TestAckReceiptSurvivesRestart(t *testing.T) {
	// Given a receipt durably recorded for the first of two events.
	o := journalOptions(t)
	j := openJournal(t, o)
	first := appendEvidence(t, j)
	second := appendEvidence(t, j)
	if err := j.Ack(context.Background(), first.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// When reopened, only the second event is deliverable.
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != second.EventID {
		t.Fatalf("delivery after ACK: %s %v %v", got.EventID, ok, err)
	}
}

func TestAckRemoteReceiptWithoutLocalCheckpointReplays(t *testing.T) {
	// Given admitted evidence and a remote receipt not yet passed to Ack.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := appendEvidence(t, j)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// When restarted, the same immutable event identity remains eligible.
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != e.EventID {
		t.Fatalf("uncertain receipt replay: %v %v", ok, err)
	}
}

func TestAckCheckpointFlushFailurePoisonsUntilRestart(t *testing.T) {
	// Given a real checkpoint whose flush fails before publication.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := appendEvidence(t, j)
	j.fault = func(operation, name string) error {
		if operation == "before-file-sync" {
			return os.ErrPermission
		}
		return nil
	}
	// When ACK fails, the current process must retain the event and stop writes.
	if err := j.Ack(context.Background(), e.EventID, testReceipt); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ACK fault: %v", err)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || !ok {
		t.Fatalf("failed ACK hid evidence: %v %v", ok, err)
	}
	if err := j.Append(context.Background(), journalEvent(t, o)); err == nil {
		t.Fatal("accepted append after uncertain checkpoint")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	if _, ok, err := j.Peek(context.Background()); err != nil || !ok {
		t.Fatalf("unpublished ACK recovered: %v %v", ok, err)
	}
}

func TestQuarantineSkipsDeliveryWithoutAcknowledgingPayload(t *testing.T) {
	// Given quarantined evidence followed by another event.
	o := journalOptions(t)
	j := openJournal(t, o)
	first := appendEvidence(t, j)
	second := appendEvidence(t, j)
	if err := j.Quarantine(context.Background(), first.EventID, "permanent_rejection"); err != nil {
		t.Fatal(err)
	}
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// When reopened, delivery continues and quarantine is distinct from receipt.
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	h := j.Snapshot()
	if err != nil || !ok || got.EventID != second.EventID || h.Quarantined != 1 || h.LastReceiptAt != nil {
		t.Fatalf("quarantine: %#v %v %v", h, ok, err)
	}
	if err := j.Ack(context.Background(), first.EventID, testReceipt); !errors.Is(err, ErrTerminal) {
		t.Fatalf("quarantined event ACK: %v", err)
	}
}

func TestCompactPreservesCursorsAfterDeletingAllDeliveredSegments(t *testing.T) {
	// Given a baseline and a fully receipt-covered segment.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := appendEvidence(t, j)
	c := Cursor{Source: "legacy", Identity: "migration", Generation: "complete", Offset: 99, Empty: true}
	if err := j.SaveBaseline(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	old := j.segments[0].name
	// When compacted and restarted, cursor snapshots outlive deleted payload.
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(o.Dir + string(os.PathSeparator) + old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delivered segment retained: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	if got, ok := j.Cursor("legacy"); !ok || got != c {
		t.Fatalf("legacy cursor: %#v %v", got, ok)
	}
	if got, ok := j.Cursor("syslog"); !ok || got.Offset != 42 {
		t.Fatalf("source cursor: %#v %v", got, ok)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("delivered replay: %v %v", ok, err)
	}
	appendEvidence(t, j)
}

func TestAttemptFirstTimestampSurvivesRestartAndThirtyDayHold(t *testing.T) {
	// Given the first persisted attempt, a retry may not refresh uncertainty.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := appendEvidence(t, j)
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := j.MarkAttempt(context.Background(), e.EventID, first); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkAttempt(context.Background(), e.EventID, first.Add(29*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	got, ok, err := j.FirstAttempt(context.Background(), e.EventID)
	if err != nil || !ok || !got.Equal(first) {
		t.Fatalf("first attempt: %v %v %v", got, ok, err)
	}
	// When the Sender/operator holds at the 30-day boundary, retain its payload.
	if err := j.Hold(context.Background(), e.EventID, "uncertainty_window"); err != nil {
		t.Fatal(err)
	}
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("held delivery: %v %v", ok, err)
	}
	if h := j.Snapshot(); h.Held != 1 || h.Retries != 1 {
		t.Fatalf("hold/retries: %#v", h)
	}
}
