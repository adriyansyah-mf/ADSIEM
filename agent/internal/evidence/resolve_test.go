package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// heldAndQuarantined admits three events: one held, one quarantined, one pending.
func heldAndQuarantined(t *testing.T) (*Journal, Envelope, Envelope, Envelope) {
	t.Helper()
	j := openJournal(t, journalOptions(t))
	ctx := context.Background()
	held, quarantined, pending := journalEvent(t, j.options), journalEvent(t, j.options), journalEvent(t, j.options)
	for _, e := range []Envelope{held, quarantined, pending} {
		if err := j.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.MarkAttempt(ctx, held.EventID, time.Now().Add(-31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := j.Hold(ctx, held.EventID, "receipt_uncertainty_window"); err != nil {
		t.Fatal(err)
	}
	if err := j.Quarantine(ctx, quarantined.EventID, "rejected_status_422"); err != nil {
		t.Fatal(err)
	}
	return j, held, quarantined, pending
}

func TestResolveRequiresAReasonAndChangesNothingWithout(t *testing.T) {
	j, held, quarantined, _ := heldAndQuarantined(t)
	for _, action := range []string{"release", "discard"} {
		if err := j.Resolve(context.Background(), quarantined.EventID, action, "", true); !errors.Is(err, ErrInvalidControl) {
			t.Fatalf("%s without a reason: %v", action, err)
		}
	}
	records, _, err := j.Records(context.Background())
	if err != nil || len(records) != 2 {
		t.Fatalf("records changed: %v %v", records, err)
	}
	if len(j.Audit()) != 0 {
		t.Fatal("a refused action was audited")
	}
	_ = held
}

func TestReleaseOfHeldEvidenceNeedsDuplicateConsent(t *testing.T) {
	j, held, _, pending := heldAndQuarantined(t)
	ctx := context.Background()
	if err := j.Resolve(ctx, held.EventID, "release", "server restored from backup", false); !errors.Is(err, ErrDuplicateRisk) {
		t.Fatalf("held release without consent: %v", err)
	}
	if err := j.Resolve(ctx, held.EventID, "release", "server restored from backup", true); err != nil {
		t.Fatal(err)
	}
	// released: deliverable again, with a fresh uncertainty window
	if _, attempted, err := j.FirstAttempt(ctx, held.EventID); err != nil || attempted {
		t.Fatalf("first attempt kept: %v %v", attempted, err)
	}
	var queue []string
	for {
		e, ok, err := j.Peek(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		queue = append(queue, e.EventID)
		if err := j.Ack(ctx, e.EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(queue, ",") != held.EventID+","+pending.EventID {
		t.Fatalf("released event not deliverable in order: %v", queue)
	}
	audit := j.Audit()
	if len(audit) != 1 || audit[0].Action != "release" || audit[0].EventID != held.EventID ||
		audit[0].PriorState != "held" || audit[0].Reason != "server restored from backup" || !audit[0].DuplicateRisk {
		t.Fatalf("audit %+v", audit)
	}
}

func TestReleaseOfQuarantinedEvidenceRetriesIt(t *testing.T) {
	j, _, quarantined, _ := heldAndQuarantined(t)
	if err := j.Resolve(context.Background(), quarantined.EventID, "release", "server validation fixed", false); err != nil {
		t.Fatal(err)
	}
	e, ok, err := j.Peek(context.Background())
	if err != nil || !ok || e.EventID != quarantined.EventID {
		t.Fatalf("quarantined event not released: %v %v %v", e.EventID, ok, err)
	}
}

func TestDiscardIsDurableAuditedAndOnlyForParkedEvidence(t *testing.T) {
	j, held, quarantined, pending := heldAndQuarantined(t)
	ctx := context.Background()
	if err := j.Resolve(ctx, pending.EventID, "discard", "no", false); !errors.Is(err, ErrNotResolvable) {
		t.Fatalf("pending backlog discarded: %v", err)
	}
	if err := j.Resolve(ctx, quarantined.EventID, "discard", "malformed test data", false); err != nil {
		t.Fatal(err)
	}
	if err := j.Resolve(ctx, held.EventID, "frobnicate", "x", true); !errors.Is(err, ErrInvalidControl) {
		t.Fatalf("unknown action: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, j.options) // the tombstone and its audit survive a restart
	records, pendingCount, err := j.Records(ctx)
	if err != nil || len(records) != 1 || records[0].EventID != held.EventID || pendingCount != 1 {
		t.Fatalf("after discard: %+v pending=%d %v", records, pendingCount, err)
	}
	if h := j.Snapshot(); h.QueuedEvents != 2 {
		t.Fatalf("discarded event still queued: %+v", h)
	}
	audit := j.Audit()
	if len(audit) != 1 || audit[0].Action != "discard" || audit[0].PriorState != "quarantined" {
		t.Fatalf("audit %+v", audit)
	}
	if err := j.Resolve(ctx, quarantined.EventID, "discard", "again", false); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("second discard: %v", err)
	}
}

func TestRecordsListParkedEvidenceWithoutPayload(t *testing.T) {
	j, held, quarantined, _ := heldAndQuarantined(t)
	records, pending, err := j.Records(context.Background())
	if err != nil || pending != 1 || len(records) != 2 {
		t.Fatalf("%+v %d %v", records, pending, err)
	}
	byID := map[string]RecordInfo{}
	for _, r := range records {
		byID[r.EventID] = r
	}
	if r := byID[held.EventID]; r.State != "held" || r.Reason != "receipt_uncertainty_window" || r.FirstAttempt.IsZero() || r.Bytes <= 0 || r.LogType != "syslog" {
		t.Fatalf("held record %+v", r)
	}
	if r := byID[quarantined.EventID]; r.State != "quarantined" || r.Reason != "rejected_status_422" {
		t.Fatalf("quarantined record %+v", r)
	}
}

func TestAuditIsBounded(t *testing.T) {
	o := journalOptions(t)
	o.ReservedBytes = 256 << 10 // the audit lives in the control budget (16 MiB by default)
	j := openJournal(t, o)
	ctx := context.Background()
	for i := 0; i < maxAudit+5; i++ {
		e := journalEvent(t, j.options)
		if err := j.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		if err := j.Quarantine(ctx, e.EventID, "rejected_status_400"); err != nil {
			t.Fatal(err)
		}
		if err := j.Resolve(ctx, e.EventID, "discard", "bulk cleanup", false); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(j.Audit()); got != maxAudit {
		t.Fatalf("audit length %d", got)
	}
}
