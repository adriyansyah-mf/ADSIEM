package evidence

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPendingLossFlushPreservesCumulativeUnknownGaps(t *testing.T) {
	// Given prior cumulative health and a worker paused in its unlocked observer.
	j := openJournal(t, journalOptions(t))
	if err := j.RecordLoss(context.Background(), "prior", "rotation_gap", 2, true); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	p := NewPublisher(j, j.options.AgentID, "host", func(Envelope) { close(entered); <-release })
	if err := p.TrySubmit(Draft{}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, entered)
	if err := p.TrySubmit(Draft{RawMessage: strings.Repeat("x", j.options.MaxEventBytes+1)}); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	before := j.Snapshot()
	// When the pending accounting later reaches disk.
	close(release)
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	after := j.Snapshot()
	// Then only the durable reason counter moves; cumulative unknown gaps do not decrease.
	if before.PendingLoss["oversize"] != 1 || before.KnownLoss["oversize"] != 0 || !before.LossUncertain || before.UnknownGaps != 1 {
		t.Fatalf("pending: %#v", before)
	}
	if len(after.PendingLoss) != 0 || after.KnownLoss["oversize"] != 1 || after.LossUncertain || after.UnknownGaps != 1 || after.KnownLoss["rotation_gap"] != 2 {
		t.Fatalf("flushed: %#v", after)
	}
}

func TestLossCheckpointFailureRetainsUnpersistedCounters(t *testing.T) {
	// Given a healthy event journal but failing health persistence.
	j := openJournal(t, journalOptions(t))
	j.fault = func(operation, name string) error {
		if operation == "before-file-sync" {
			return os.ErrPermission
		}
		return nil
	}
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	// When the bridge rejects oversized input and the loss checkpoint cannot flush.
	if err := p.TrySubmit(Draft{RawMessage: strings.Repeat("x", j.options.MaxEventBytes+1)}); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	err := stopPublisher(t, p)
	// Then the worker is stopped, with explicit persistence failure and visible pending loss.
	if !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrPublisherRunning) {
		t.Fatalf("stop: %v", err)
	}
	h := j.Snapshot()
	if h.PendingLoss["oversize"] != 1 || h.KnownLoss["oversize"] != 0 || !h.LossUncertain || h.Reason != "storage_failure" {
		t.Fatalf("health: %#v", h)
	}
}

func TestLossPublicationCleanupFailureDoesNotDoubleCount(t *testing.T) {
	// Given a prior generation so the next publication must clean it up.
	j := openJournal(t, journalOptions(t))
	if err := j.RecordLoss(context.Background(), "prior", "source_failure", 1, false); err != nil {
		t.Fatal(err)
	}
	j.fault = func(operation, name string) error {
		if operation == "before-remove" {
			return os.ErrPermission
		}
		return nil
	}
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	// When loss publication commits but cleanup fails.
	if err := p.TrySubmit(Draft{RawMessage: strings.Repeat("x", j.options.MaxEventBytes+1)}); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	if err := stopPublisher(t, p); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cleanup error: %v", err)
	}
	// Then committed loss is not retained as a second volatile loss.
	h := j.Snapshot()
	if h.KnownLoss["oversize"] != 1 || len(h.PendingLoss) != 0 {
		t.Fatalf("double accounting: %#v", h)
	}
}

func TestSaturatedLossUncertaintyRemainsVisibleAfterFlush(t *testing.T) {
	// Given counters at their exact-representation boundary.
	j := openJournal(t, journalOptions(t))
	j.bridgeLoss.counts[0] = maxCounter
	j.pendingBridgeLoss(ErrBridgeFull)
	before := j.Snapshot()
	// When representable counters flush, the uncountable excess stays uncertain.
	if err := j.flushBridgeLoss(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := j.Snapshot()
	if before.UnknownGaps != 1 || after.UnknownGaps != 1 || !after.LossUncertain || after.KnownLoss["capacity"] != maxCounter {
		t.Fatalf("saturation before=%#v after=%#v", before, after)
	}
}
