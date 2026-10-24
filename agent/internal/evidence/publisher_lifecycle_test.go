package evidence

import (
	"context"
	"errors"
	"testing"
)

func TestBridgeObserverCanReenterTrySubmit(t *testing.T) {
	// Given an observer which emits a local-detection event from the worker.
	j := openJournal(t, journalOptions(t))
	observed := make(chan struct{})
	var p *Publisher
	p = NewPublisher(j, j.options.AgentID, "host", func(Envelope) {
		if err := p.TrySubmit(Draft{LogType: "local_detection"}); err != nil {
			t.Error(err)
		}
		close(observed)
	})
	// When a live bridge event reaches the detector.
	if err := p.TrySubmit(Draft{LogType: "syslog"}); err != nil {
		t.Fatal(err)
	}
	waitPublisherSignal(t, observed)
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
	// Then local output is durably admitted without recursion or a lifecycle lock deadlock.
	if j.Snapshot().QueuedEvents != 2 {
		t.Fatal("missing reentrant detector output")
	}
}

func TestStopTracksSynchronousSubmitUntilObserverFinishes(t *testing.T) {
	// Given an already durable Submit still executing its observer outside locks.
	j := openJournal(t, journalOptions(t))
	entered, release := make(chan struct{}), make(chan struct{})
	p := NewPublisher(j, j.options.AgentID, "host", func(Envelope) { close(entered); <-release })
	finished := make(chan error, 1)
	go func() { _, err := p.Submit(context.Background(), Draft{}); finished <- err }()
	waitPublisherSignal(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// When Stop reaches its deadline before tracked synchronous work returns.
	err := p.Stop(ctx)
	// Then it must not claim that all work stopped or allow a journal lifetime race.
	if !errors.Is(err, ErrPublisherRunning) {
		t.Fatalf("untracked Submit: %v", err)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := stopPublisher(t, p); err != nil {
		t.Fatal(err)
	}
}
