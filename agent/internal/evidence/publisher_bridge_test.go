package evidence

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrySubmitBoundsQueueWithoutWaitingForJournal(t *testing.T) {
	// Given a worker blocked in journal fsync.
	j := openJournal(t, journalOptions(t))
	g := gatePublisherSync(t, j)
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	if err := p.TrySubmit(Draft{RawMessage: "active"}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, g.entered)
	finished := make(chan error, 1)
	// When the callback fills the 64 pending slots then rejects another offer.
	go func() {
		for range 64 {
			if err := p.TrySubmit(Draft{RawMessage: "pending"}); err != nil {
				finished <- err
				return
			}
		}
		finished <- p.TrySubmit(Draft{RawMessage: "overflow"})
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrBridgeFull) {
			t.Fatalf("overload: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callback waited for journal lock/fsync")
	}
	g.unblock()
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	// Then admitted work drains, and the rejected item is durably counted.
	h := j.Snapshot()
	if h.QueuedEvents != 65 || h.KnownLoss["capacity"] != 1 || len(h.PendingLoss) != 0 || h.LossUncertain {
		t.Fatalf("bridge health: %#v", h)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, j.options)
	if h = j.Snapshot(); h.KnownLoss["capacity"] != 1 {
		t.Fatalf("loss did not survive reopen: %#v", h)
	}
}

func TestTrySubmitSnapshotsIdentityTimeAndCursorAtOffer(t *testing.T) {
	// Given a blocked journal and a controllable collection clock.
	j := openJournal(t, journalOptions(t))
	g := gatePublisherSync(t, j)
	var clock atomic.Int64
	clock.Store(1)
	j.now = func() time.Time { return time.Unix(clock.Load(), 0).UTC() }
	observed := make(chan Envelope, 2)
	p := NewPublisher(j, j.options.AgentID, "host", func(e Envelope) { observed <- e })
	if err := p.TrySubmit(Draft{RawMessage: "active"}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, g.entered)
	cursor := Cursor{Source: "source", Identity: "inode", Offset: 7}
	// When an offer waits behind disk work, the source later moves ahead.
	if err := p.TrySubmit(Draft{RawMessage: "snapshot", Cursor: &cursor}); err != nil {
		t.Fatal(err)
	}
	cursor.Offset = 99
	clock.Store(2)
	g.unblock()
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	<-observed
	got := <-observed
	// Then the event preserves the offered cursor and collection time.
	if got.Cursor.Offset != 7 || !got.CollectedAt.Equal(time.Unix(1, 0)) || ValidateAgentID(got.EventID) != nil {
		t.Fatalf("delayed snapshot: %#v", got)
	}
	if c, _ := j.Cursor("source"); c.Offset != 7 {
		t.Fatalf("committed cursor: %#v", c)
	}
}

func TestBridgeFailureExposesUnpersistedLossAndStoppedError(t *testing.T) {
	// Given storage which fails both event flush and later health publication.
	j := openJournal(t, journalOptions(t))
	if err := j.SaveBaseline(context.Background(), Cursor{Source: "baseline"}); err != nil {
		t.Fatal(err)
	}
	j.writer = syncFault{j.writer}
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	// When a bridge-accepted event fails durable admission.
	if err := p.TrySubmit(Draft{LogType: "syslog"}); err != nil {
		t.Fatal(err)
	}
	err := stopPublisher(t, p)
	// Then Stop reports the completed failure, and health does not invent durability.
	if !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrPublisherRunning) {
		t.Fatalf("stop: %v", err)
	}
	h := j.Snapshot()
	if h.PendingLoss["storage_failure"] != 1 || h.KnownLoss["storage_failure"] != 0 || !h.LossUncertain || h.UnknownGaps == 0 || h.State != "degraded" {
		t.Fatalf("invisible loss: %#v", h)
	}
	h.PendingLoss["storage_failure"] = 999
	if j.Snapshot().PendingLoss["storage_failure"] != 1 {
		t.Fatal("snapshot aliases pending counters")
	}
}

func TestBridgeOversizeRefusalIsDurablyCounted(t *testing.T) {
	// Given a bounded event limit.
	j := openJournal(t, journalOptions(t))
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	// When the bridge refuses an oversized event before retaining it.
	err := p.TrySubmit(Draft{RawMessage: strings.Repeat("x", j.options.MaxEventBytes+1)})
	if !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize: %v", err)
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	// Then the loss is accounted without an admitted payload.
	h := j.Snapshot()
	if h.QueuedEvents != 0 || h.KnownLoss["oversize"] != 1 {
		t.Fatalf("oversize health: %#v", h)
	}
}

func TestStopDeadlineDoesNotClaimActiveAppendStopped(t *testing.T) {
	// Given an active append stuck in disk flush.
	j := openJournal(t, journalOptions(t))
	g := gatePublisherSync(t, j)
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	if err := p.TrySubmit(Draft{}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, g.entered)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// When shutdown cannot join the active worker before its deadline.
	err := p.Stop(ctx)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrPublisherRunning) {
		t.Fatalf("unsafe stop result: %v", err)
	}
	if err := p.TrySubmit(Draft{}); !errors.Is(err, ErrPublisherStopped) {
		t.Fatalf("admission after stop: %v", err)
	}
	if _, err := p.Submit(context.Background(), Draft{}); !errors.Is(err, ErrPublisherStopped) {
		t.Fatalf("sync admission after stop: %v", err)
	}
	g.unblock()
	// Then a subsequent successful join makes closing the journal safe.
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	if j.Snapshot().QueuedEvents != 1 {
		t.Fatal("active append was silently abandoned")
	}
}
