package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
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
	sender    atomic.Pointer[evidence.Sender]
	cancel    context.CancelFunc
	done      chan struct{}

	importCancel context.CancelFunc
	importDone   chan struct{}

	reportMu   sync.Mutex
	lastReport *evidence.Health
	reportedAt time.Time
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

// evidenceReport is the heartbeat's evidence_health: the journal's cumulative
// health (it survives restarts and failed heartbeats) plus the sender state.
type evidenceReport struct {
	evidence.Health
	Mode   string                 `json:"mode"`
	Sender *evidence.SenderStatus `json:"sender,omitempty"`
}

// healthEvery bounds how often a heartbeat rescans the journal: Snapshot
// walks every retained record, so a large backlog makes it expensive.
const healthEvery = time.Minute

// report returns the evidence health for the next heartbeat.
func (rt *durableRuntime) report() any {
	if rt.journal == nil {
		return evidenceReport{Mode: "durable", Health: evidence.Health{
			Version: 1, State: "degraded", Reason: "journal_unavailable",
			KnownLoss: map[string]int64{}, PendingLoss: map[string]int64{}, Sources: map[string]evidence.SourceHealth{},
		}}
	}
	rt.reportMu.Lock()
	defer rt.reportMu.Unlock()
	if rt.lastReport == nil || time.Since(rt.reportedAt) >= healthEvery {
		h := rt.journal.Snapshot()
		if h.KnownLoss == nil {
			h.KnownLoss = map[string]int64{}
		}
		if h.PendingLoss == nil {
			h.PendingLoss = map[string]int64{}
		}
		if h.Sources == nil {
			h.Sources = map[string]evidence.SourceHealth{}
		}
		rt.lastReport, rt.reportedAt = &h, time.Now()
	}
	r := evidenceReport{Health: *rt.lastReport, Mode: "durable"}
	if sender := rt.sender.Load(); sender != nil { // set by startSender after the heartbeat starts
		s := sender.Status()
		if s.State != "" {
			r.Sender = &s
		}
	}
	return r
}

func (rt *durableRuntime) startSender(t evidence.Transport, supportsV2 func() bool, batchMax func() int) {
	if rt.journal == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt.cancel, rt.done = cancel, make(chan struct{})
	sender := &evidence.Sender{Journal: rt.journal, Transport: t, SupportsV2: supportsV2, BatchMax: batchMax}
	rt.sender.Store(sender)
	go func() {
		defer close(rt.done)
		_ = sender.Run(ctx)
	}()
}

// importRetry is how often a migration blocked by a full journal is retried.
var importRetry = time.Minute

// importLegacy moves the legacy disk spill into the journal before any
// producer starts: the legacy spill writer never runs in durable mode, so
// this is its only reader. The spill file itself is left untouched. When the
// journal is full the import keeps its progress and is retried in the
// background as delivery frees space; collection starts meanwhile.
func (rt *durableRuntime) importLegacy(path, agentID, hostname string) {
	if rt.journal == nil || path == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := evidence.ImportLegacy(ctx, rt.journal, path, agentID, hostname)
	if err == nil {
		cancel()
		if fi, statErr := os.Stat(path); statErr == nil && fi.Size() > 0 {
			slog.Info("legacy spill imported into the evidence journal (the file is kept)", "path", path)
		}
		return
	}
	slog.Warn("legacy spill import incomplete, retrying in the background", "path", path, "err", err, "retry_in", importRetry)
	rt.importCancel, rt.importDone = cancel, make(chan struct{})
	go func() {
		defer close(rt.importDone)
		t := time.NewTicker(importRetry)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			err := evidence.ImportLegacy(ctx, rt.journal, path, agentID, hostname)
			if err == nil {
				slog.Info("legacy spill imported into the evidence journal (the file is kept)", "path", path)
				return
			}
			if ctx.Err() != nil {
				return
			}
			if !errors.Is(err, evidence.ErrMigrationBlocked) {
				slog.Error("legacy spill import failed", "path", path, "err", err)
			}
		}
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
	if rt.importCancel != nil {
		rt.importCancel()
		<-rt.importDone
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
