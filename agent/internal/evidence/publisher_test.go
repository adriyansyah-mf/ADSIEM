package evidence

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type publisherSyncGate struct {
	storage
	entered, release chan struct{}
	once             sync.Once
	released         sync.Once
}

func (g *publisherSyncGate) unblock() { g.released.Do(func() { close(g.release) }) }

func (g *publisherSyncGate) Sync() error {
	g.once.Do(func() { close(g.entered); <-g.release })
	return g.storage.Sync()
}

func gatePublisherSync(t *testing.T, j *Journal) *publisherSyncGate {
	t.Helper()
	if err := j.SaveBaseline(context.Background(), Cursor{Source: "baseline", Offset: 1}); err != nil {
		t.Fatal(err)
	}
	g := &publisherSyncGate{storage: j.writer, entered: make(chan struct{}), release: make(chan struct{})}
	j.writer = g
	t.Cleanup(g.unblock)
	return g
}

func waitPublisherSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not reach expected boundary")
	}
}

func stopPublisher(t *testing.T, p *Publisher) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return p.Stop(ctx)
}

func TestPublisherSubmitWaitsForDurableFlush(t *testing.T) {
	// Given a journal whose data flush is blocked.
	j := openJournal(t, journalOptions(t))
	g := gatePublisherSync(t, j)
	observed := make(chan struct{}, 1)
	p := NewPublisher(j, j.options.AgentID, "host", func(Envelope) { observed <- struct{}{} })
	finished := make(chan error, 1)
	// When synchronous admission reaches fsync.
	go func() { _, err := p.Submit(context.Background(), Draft{LogType: "syslog"}); finished <- err }()
	waitPublisherSignal(t, g.entered)
	select {
	case err := <-finished:
		t.Fatalf("memory-only success: %v", err)
	case <-observed:
		t.Fatal("observed before durable admission")
	default:
	}
	g.unblock()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherSubmitRefusesStorageFailure(t *testing.T) {
	// Given a journal with a failing flush.
	j := openJournal(t, journalOptions(t))
	if err := j.SaveBaseline(context.Background(), Cursor{Source: "source", Offset: 1}); err != nil {
		t.Fatal(err)
	}
	j.writer = syncFault{j.writer}
	observed := false
	p := NewPublisher(j, j.options.AgentID, "host", func(Envelope) { observed = true })
	// When durable admission fails.
	_, err := p.Submit(context.Background(), Draft{Cursor: &Cursor{Source: "source", Offset: 2}})
	// Then neither the replay cursor nor detector advances.
	if !errors.Is(err, os.ErrPermission) || observed {
		t.Fatalf("admission: %v, observed=%v", err, observed)
	}
	if c, _ := j.Cursor("source"); c.Offset != 1 {
		t.Fatalf("cursor: %#v", c)
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherPressurePreservesReplayCursor(t *testing.T) {
	// Given an exhausted data budget and a committed baseline.
	o := journalOptions(t)
	o.MaxBytes = 32768
	o.SegmentBytes = 4096
	o.ReservedBytes = 8192
	o.MaxEventBytes = 2048
	j := openJournal(t, o)
	if err := j.SaveBaseline(context.Background(), Cursor{Source: "source", Offset: 1}); err != nil {
		t.Fatal(err)
	}
	for {
		e := journalEvent(t, o)
		e.RawMessage = strings.Repeat("x", 1000)
		e.Cursor = nil
		err := j.Append(context.Background(), e)
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	p := NewPublisher(j, o.AgentID, "host", nil)
	// When a replayable collector attempts another admission.
	_, err := p.Submit(context.Background(), Draft{RawMessage: strings.Repeat("x", 1000), Cursor: &Cursor{Source: "source", Offset: 2}})
	// Then pressure is explicit and the cursor remains replayable.
	if !errors.Is(err, ErrFull) {
		t.Fatalf("pressure: %v", err)
	}
	if c, _ := j.Cursor("source"); c.Offset != 1 {
		t.Fatalf("cursor: %#v", c)
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherObservesLiveAdmissionOnceAndAllowsReentrantEmission(t *testing.T) {
	// Given backlog and a detector which emits its own local event.
	j := openJournal(t, journalOptions(t))
	appendEvidence(t, j)
	calls := 0
	var p *Publisher
	p = NewPublisher(j, j.options.AgentID, "host", func(Envelope) {
		calls++
		if _, err := p.Submit(context.Background(), Draft{LogType: "local_detection"}); err != nil {
			t.Error(err)
		}
	})
	// When a live event is admitted and the sender rereads its backlog.
	if _, err := p.Submit(context.Background(), Draft{LogType: "syslog"}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, _, err := j.Peek(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Then detector output does not recurse and retries/backlog do not reobserve.
	if calls != 1 || j.Snapshot().QueuedEvents != 3 {
		t.Fatalf("observe=%d health=%#v", calls, j.Snapshot())
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
}
