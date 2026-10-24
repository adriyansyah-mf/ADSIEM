package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/detect"
	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/tailer"
)

// errJournalUnavailable drops producer offers while the journal cannot open:
// collection is visibly blocked (heartbeat buffer_dropped) rather than silently
// routed to the legacy queue.
var errJournalUnavailable = errors.New("durable evidence journal unavailable")

const publisherStopTimeout = 10 * time.Second

// durableRuntime is evidence.enabled mode: producers push into a sink buffer
// that offers each entry to the journal publisher, local detection observes
// every live admitted event once, and the Sender reclaims an event only for a
// matching durable receipt. The legacy sender and disk spill are never used.
type durableRuntime struct {
	journal   *evidence.Journal // nil when it failed to open
	publisher *evidence.Publisher
	buf       *buffer.Buffer
	detector  atomic.Pointer[detect.Engine]
	sender    *evidence.Sender
	cancel    context.CancelFunc
	done      chan struct{}
}

func openDurable(cfg *config.Config, hostname string) *durableRuntime {
	rt := &durableRuntime{}
	e := cfg.Evidence
	j, err := evidence.Open(evidence.Options{
		Dir: e.Dir, AgentID: cfg.Agent.ID,
		MaxBytes: e.MaxBytes, SegmentBytes: e.SegmentBytes, ReservedBytes: e.ReservedBytes, MaxEventBytes: e.MaxEventBytes,
	})
	if err != nil {
		slog.Error("durable evidence journal unavailable; evidence collection is blocked until it is fixed", "dir", e.Dir, "err", err)
		rt.buf = buffer.NewWithSink(func(string) error { return errJournalUnavailable })
		return rt
	}
	rt.journal = j
	rt.publisher = evidence.NewPublisher(j, cfg.Agent.ID, hostname, rt.observe)
	// Today's producers (tailers, eBPF monitors, firewall, local detection) are
	// not replayable: their entries are bridge offers, not durable admissions.
	rt.buf = buffer.NewWithSink(func(entry string) error {
		logType, location, raw := tailer.Decode(entry)
		return rt.publisher.TrySubmit(evidence.Draft{LogType: logType, Location: location, RawMessage: raw})
	})
	slog.Info("durable evidence mode", "dir", e.Dir, "max_bytes", e.MaxBytes)
	return rt
}

// observe runs local detection on every live admitted event, before and
// independent of delivery, so it keeps working while the server is down.
// Its own local_detection events are not observed (evidence.Publisher).
func (rt *durableRuntime) observe(e evidence.Envelope) {
	if d := rt.detector.Load(); d != nil {
		d.Emit(d.Observe(e.LogType, e.RawMessage))
	}
}

func (rt *durableRuntime) setDetector(d *detect.Engine) {
	if d != nil {
		rt.detector.Store(d)
	}
}

func (rt *durableRuntime) startSender(t evidence.Transport, supportsV2 func() bool) {
	if rt.journal == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt.cancel, rt.done = cancel, make(chan struct{})
	rt.sender = &evidence.Sender{Journal: rt.journal, Transport: t, SupportsV2: supportsV2}
	go func() {
		defer close(rt.done)
		_ = rt.sender.Run(ctx)
	}()
}

// shutdown runs after every producer was stopped: stop the sender, drain the
// publisher, then close the journal. A publisher that is still appending past
// its deadline keeps the journal open (closing it would race the append); the
// lock is released when the process exits.
func (rt *durableRuntime) shutdown() {
	if rt.journal == nil {
		return
	}
	if rt.cancel != nil {
		rt.cancel()
		<-rt.done
	}
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), publisherStopTimeout)
		err := rt.publisher.Stop(ctx)
		cancel()
		if !errors.Is(err, evidence.ErrPublisherRunning) {
			if err != nil {
				slog.Warn("evidence publisher stopped with unpersisted loss", "err", err)
			}
			break
		}
		if attempt == 3 {
			slog.Error("evidence publisher still appending; leaving the journal open", "err", err)
			return
		}
	}
	if err := rt.journal.Close(); err != nil {
		slog.Warn("closing evidence journal", "err", err)
	}
}
