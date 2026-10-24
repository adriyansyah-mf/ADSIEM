package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHealthCountersPersistAndSnapshotsAreCopies(t *testing.T) {
	// Given durable loss and source status updates.
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.RecordLoss(context.Background(), "syslog", "storage_failure", 3, true); err != nil {
		t.Fatal(err)
	}
	if err := j.SetSourceState(context.Background(), "syslog", "degraded", "reader_failed"); err != nil {
		t.Fatal(err)
	}
	h := j.Snapshot()
	h.KnownLoss["storage_failure"] = 999
	delete(h.Sources, "syslog")
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// When restarted, prior heartbeat snapshots have not reset/mutated counters.
	j = openJournal(t, o)
	h = j.Snapshot()
	if h.KnownLoss["storage_failure"] != 3 || h.UnknownGaps != 1 || h.Sources["syslog"].State != "degraded" {
		t.Fatalf("health recovery: %#v", h)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "state", "reason", "queued_events", "queued_bytes", "oldest_queued_at", "last_receipt_at", "retries", "quarantined", "held", "known_loss", "unknown_gaps", "sources"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing health field %s", key)
		}
	}
}

func TestHealthStorageFailureVisibleWithoutDurableCounter(t *testing.T) {
	// Given storage which cannot flush the health checkpoint.
	j := openJournal(t, journalOptions(t))
	j.fault = func(operation, name string) error {
		if operation == "before-file-sync" {
			return os.ErrPermission
		}
		return nil
	}
	// When persistence fails, health still exposes an unknown collection gap.
	if err := j.RecordLoss(context.Background(), "syslog", "storage_failure", 0, true); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("loss fault: %v", err)
	}
	h := j.Snapshot()
	if h.State != "degraded" || h.Reason != "storage_failure" || h.UnknownGaps == 0 {
		t.Fatalf("invisible storage failure: %#v", h)
	}
}

func TestHealthReceiptClockAndQueuedGauges(t *testing.T) {
	// Given two queued events and an injected journal clock.
	j := openJournal(t, journalOptions(t))
	first := appendEvidence(t, j)
	appendEvidence(t, j)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	// When one receipt is acknowledged, the clock and remaining queue agree.
	if err := j.Ack(context.Background(), first.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	h := j.Snapshot()
	if h.QueuedEvents != 1 || h.QueuedBytes <= 0 || h.OldestQueuedAt == nil || h.LastReceiptAt == nil || !h.LastReceiptAt.Equal(now) {
		t.Fatalf("receipt/queue health: %#v", h)
	}
}

func TestBudgetDataFullLeavesRoomForControl(t *testing.T) {
	// Given an exhausted data allowance with a separate reserved control slice.
	o := journalOptions(t)
	o.MaxBytes = 32768
	o.SegmentBytes = 4096
	o.ReservedBytes = 8192
	o.MaxEventBytes = 2048
	j := openJournal(t, o)
	first := appendEvidence(t, j)
	for {
		e := journalEvent(t, o)
		e.RawMessage = strings.Repeat("x", 1000)
		err := j.Append(context.Background(), e)
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// When receipt and health are persisted, retained evidence stays in budget.
	if err := j.Ack(context.Background(), first.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordLoss(context.Background(), "syslog", "capacity", 1, true); err != nil {
		t.Fatal(err)
	}
	if j.used > o.MaxBytes {
		t.Fatalf("quota exceeded: %d", j.used)
	}
}
