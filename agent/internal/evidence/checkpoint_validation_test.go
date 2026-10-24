package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAckCommittedCheckpointCorruptionNeverRollsBack(t *testing.T) {
	for _, kind := range []string{"checkpoint", "commit", "selected-segment"} {
		t.Run(kind, func(t *testing.T) {
			// Given a committed receipt plus retained evidence in that generation.
			o := journalOptions(t)
			j := openJournal(t, o)
			first := appendEvidence(t, j)
			appendEvidence(t, j)
			if err := j.Ack(context.Background(), first.EventID, testReceipt); err != nil {
				t.Fatal(err)
			}
			name := generationName(kind, j.checkpoint.Generation)
			if kind == "selected-segment" {
				name = j.segments[0].name
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "selected-segment" {
				if err := os.Remove(filepath.Join(o.Dir, name)); err != nil {
					t.Fatal(err)
				}
			} else {
				f, err := os.OpenFile(filepath.Join(o.Dir, name), os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteAt([]byte("!"), 0); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// When committed state is damaged, fail closed instead of replaying ACKs.
			opened, err := Open(o)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("committed corruption: %v", err)
			}
		})
	}
}

func TestAckIncompleteUnpublishedGenerationKeepsPriorCommit(t *testing.T) {
	// Given committed ACK state and a newer filename without a complete marker.
	o := journalOptions(t)
	j := openJournal(t, o)
	first := appendEvidence(t, j)
	second := appendEvidence(t, j)
	if err := j.Ack(context.Background(), first.EventID, testReceipt); err != nil {
		t.Fatal(err)
	}
	generation := j.checkpoint.Generation + 1
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"checkpoint", "commit"} {
		if err := os.WriteFile(filepath.Join(o.Dir, generationName(prefix, generation)), []byte("EVJ"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// When recovered, the complete prior generation remains authoritative.
	j = openJournal(t, o)
	e, ok, err := j.Peek(context.Background())
	if err != nil || !ok || e.EventID != second.EventID {
		t.Fatalf("newest filename won: %v %v", ok, err)
	}
}

func TestHealthStorageFailuresRemainVisibleAcrossControlQuotaFailure(t *testing.T) {
	// Given a real failure overlay even though reserved control space is absent.
	o := journalOptions(t)
	o.ReservedBytes = 0
	j := openJournal(t, o)
	j.writer = syncFault{j.writer}
	if err := j.Append(context.Background(), journalEvent(t, o)); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("flush failure: %v", err)
	}
	// When health cannot be durably saved, snapshots still report the gap.
	if err := j.RecordLoss(context.Background(), "syslog", "storage_failure", 0, true); err == nil {
		t.Fatal("poisoned health write succeeded")
	}
	for range 2 {
		h := j.Snapshot()
		if h.State != "degraded" || h.Reason != "storage_failure" || h.UnknownGaps != 1 {
			t.Fatalf("gap was cleared: %#v", h)
		}
	}
}

func TestHealthTerminalPayloadIsDegraded(t *testing.T) {
	// Given retained evidence requiring an operator decision.
	j := openJournal(t, journalOptions(t))
	e := appendEvidence(t, j)
	// When it is held, health must expose an actionable degraded state.
	if err := j.Hold(context.Background(), e.EventID, "uncertainty_window"); err != nil {
		t.Fatal(err)
	}
	h := j.Snapshot()
	if h.State != "degraded" || h.Reason != "held" {
		t.Fatalf("held evidence reported healthy: %#v", h)
	}
}

type cancelAfterReadContext struct {
	context.Context
	reads int
}

func (c *cancelAfterReadContext) Err() error {
	c.reads++
	if c.reads >= 3 {
		return context.Canceled
	}
	return nil
}

func TestAckCancellationDuringScanDoesNotPoisonJournal(t *testing.T) {
	// Given a context that is canceled during a bounded disk scan.
	j := openJournal(t, journalOptions(t))
	e := appendEvidence(t, j)
	ctx := &cancelAfterReadContext{Context: context.Background()}
	// When ACK is canceled before publication, normal admission remains usable.
	if err := j.Ack(ctx, e.EventID, testReceipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel scan: %v", err)
	}
	if err := j.Append(context.Background(), journalEvent(t, j.options)); err != nil {
		t.Fatalf("cancellation poisoned writer: %v", err)
	}
}

func TestAttemptTimestampValidationPreventsUndurableState(t *testing.T) {
	// Given a retained event and a date JSON cannot persist.
	j := openJournal(t, journalOptions(t))
	e := appendEvidence(t, j)
	// When marking an invalid date, reject without poisoning the journal.
	if err := j.MarkAttempt(context.Background(), e.EventID, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("accepted unencodable attempt")
	}
	if err := j.Append(context.Background(), journalEvent(t, j.options)); err != nil {
		t.Fatal(err)
	}
}

func TestAckRejectsConflictingPreexistingOccurrences(t *testing.T) {
	// Given a Task2 journal containing two differing envelopes with one ID.
	o := journalOptions(t)
	j := openJournal(t, o)
	first := appendEvidence(t, j)
	conflict := first
	conflict.RawMessage = "different legacy payload"
	data, err := json.Marshal(conflict)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.admit(context.Background(), frameEvent, data); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	// When a receipt names that ID, retain both payloads and reject ambiguity.
	if err := j.Ack(context.Background(), first.EventID, testReceipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting historic ID was ACKed: %v", err)
	}
	if h := j.Snapshot(); h.QueuedEvents != 2 || h.LastReceiptAt != nil {
		t.Fatalf("ambiguous receipt advanced delivery: %#v", h)
	}
}

func TestAckRequiresCheckpointableCursorSource(t *testing.T) {
	// Given an event cursor without its required source identity.
	j := openJournal(t, journalOptions(t))
	e := journalEvent(t, j.options)
	e.Cursor.Source = ""
	// When admission is attempted, reject before storing uncheckpointable state.
	if err := j.Append(context.Background(), e); !errors.Is(err, ErrInvalidControl) {
		t.Fatalf("unnamed source admitted: %v", err)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("invalid cursor changed queue: %v %v", ok, err)
	}
}

func TestAckGenerationExhaustionRefusesBeforePublication(t *testing.T) {
	// Given a journal whose immutable generation namespace is exhausted.
	j := openJournal(t, journalOptions(t))
	e := appendEvidence(t, j)
	j.generation = ^uint64(0)
	// When a receipt is checkpointed, reject rather than publish generation zero.
	if err := j.Ack(context.Background(), e.EventID, testReceipt); !errors.Is(err, ErrFull) {
		t.Fatalf("generation overflow accepted: %v", err)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || !ok {
		t.Fatalf("overflow lost evidence: %v %v", ok, err)
	}
}

func TestAckOldUnnamedCursorFailsClosedWithoutByteChanges(t *testing.T) {
	// Given legacy admitted bytes with an invalid unnamed event cursor.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	e.Cursor.Source = ""
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.admit(context.Background(), frameEvent, data); err != nil {
		t.Fatal(err)
	}
	name := j.segments[0].name
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.Dir, name)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// When restart detects the invalid source, fail explicitly and retain bytes.
	opened, err := Open(o)
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("legacy unnamed source: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("legacy evidence changed: %v", err)
	}
}
