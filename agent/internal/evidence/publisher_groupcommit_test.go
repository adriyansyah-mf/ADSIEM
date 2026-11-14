package evidence

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type countingSync struct {
	storage
	n *atomic.Int64
}

func (c countingSync) Sync() error {
	c.n.Add(1)
	return c.storage.Sync()
}

// A burst offered while the worker waits on one flush is admitted with a
// handful of flushes, not one per event: on a disk that takes 90 ms per fsync
// (otakunesia) one flush per event admitted about 11 events/s and the bridge
// dropped thousands of telemetry events overnight.
func TestBridgeAdmitsABurstInGroupCommits(t *testing.T) {
	j := openJournal(t, bigJournalOptions(t))
	g := gatePublisherSync(t, j)
	var syncs atomic.Int64
	g.storage = countingSync{storage: g.storage, n: &syncs}
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	if err := p.TrySubmit(Draft{RawMessage: "active"}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, g.entered)
	const burst = 2000
	for i := range burst {
		if err := p.TrySubmit(Draft{RawMessage: "burst " + strings.Repeat("x", i%50)}); err != nil {
			t.Fatalf("offer %d refused while the worker flushed: %v", i, err)
		}
	}
	g.unblock()
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	h := j.Snapshot()
	if h.QueuedEvents != burst+1 || h.KnownLoss["capacity"] != 0 {
		t.Fatalf("queued %d, loss %v", h.QueuedEvents, h.KnownLoss)
	}
	// bridgeMaxBatch events per flush, plus the first event's own flush
	if max := int64(burst/bridgeMaxBatch + 3); syncs.Load() > max {
		t.Fatalf("%d flushes for %d events, want at most %d", syncs.Load(), burst+1, max)
	}
	p.mu.Lock()
	pending := p.pendingBytes
	p.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending bytes not released: %d", pending)
	}
}

// Memory stays bounded by bytes, not only by slots: large events fill the
// byte budget long before the slots.
func TestBridgeBoundsPendingBytes(t *testing.T) {
	o := bigJournalOptions(t)
	o.MaxEventBytes = 64 << 10
	j := openJournal(t, o)
	g := gatePublisherSync(t, j)
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	if err := p.TrySubmit(Draft{RawMessage: "active"}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, g.entered)
	big := strings.Repeat("y", 60<<10)
	accepted := 0
	var err error
	for range bridgeSlots {
		if err = p.TrySubmit(Draft{RawMessage: big}); err != nil {
			break
		}
		accepted++
	}
	if !errors.Is(err, ErrBridgeFull) || accepted >= bridgeSlots || int64(accepted)*(60<<10) > bridgeBytes {
		t.Fatalf("accepted %d large events (err %v), budget %d bytes", accepted, err, bridgeBytes)
	}
	g.unblock()
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	if h := j.Snapshot(); h.KnownLoss["capacity"] != 1 {
		t.Fatalf("the refused offer is counted: %v", h.KnownLoss)
	}
}

// Dropped telemetry is logged, at most once a minute, with the count.
func TestBridgeLossIsLoggedAtMostOncePerMinute(t *testing.T) {
	var out bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	j := openJournal(t, journalOptions(t))
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC).UnixNano())
	j.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	oversized := Draft{RawMessage: strings.Repeat("x", j.options.MaxEventBytes+1)}
	for range 5 {
		_ = p.TrySubmit(oversized)
	}
	if got := strings.Count(out.String(), "telemetry dropped"); got != 1 || !strings.Contains(out.String(), "events=1") {
		t.Fatalf("first loss logged once: %q", out.String())
	}
	clock.Add(int64(61 * time.Second))
	_ = p.TrySubmit(oversized)
	if got := strings.Count(out.String(), "telemetry dropped"); got != 2 || !strings.Contains(out.String(), "events=5") {
		t.Fatalf("after a minute, one line with the count since the last: %q", out.String())
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
}

// A loss marks the bridge degraded; an hour without a new one makes it
// healthy again while KnownLoss keeps the count.
func TestBridgeLossRecoversAfterQuietHour(t *testing.T) {
	j := openJournal(t, journalOptions(t))
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC).UnixNano())
	j.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	p := NewPublisher(j, j.options.AgentID, "host", nil)
	_ = p.TrySubmit(Draft{RawMessage: strings.Repeat("x", j.options.MaxEventBytes+1)})
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	h := j.Snapshot()
	if h.State != "degraded" || h.Sources[bridgeSource].State != "degraded" || h.KnownLoss["oversize"] != 1 {
		t.Fatalf("just after the loss: %#v", h)
	}
	clock.Add(int64(59 * time.Minute))
	if h = j.Snapshot(); h.State != "degraded" {
		t.Fatalf("still within the hour: %s", h.State)
	}
	clock.Add(int64(2 * time.Minute))
	h = j.Snapshot()
	if h.State != "healthy" || h.Sources[bridgeSource].State != "healthy" ||
		h.Sources[bridgeSource].Reason != bridgeLossPast || h.KnownLoss["oversize"] != 1 {
		t.Fatalf("after a quiet hour: %#v", h)
	}
	// the stored checkpoint is not rewritten: a new loss degrades it again
	j.pendingBridgeLoss(ErrBridgeFull)
	if h = j.Snapshot(); h.State != "degraded" {
		t.Fatalf("a pending loss degrades again: %s", h.State)
	}
}
