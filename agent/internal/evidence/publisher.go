package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrBridgeFull       = errors.New("evidence: non-replayable bridge full")
	ErrPublisherStopped = errors.New("evidence: publisher admissions stopped")
	ErrPublisherRunning = errors.New("evidence: publisher still running; keep journal open and retry Stop")
)

// Bridge bounds for non-replayable input (process and network telemetry,
// local detections). The worker appends what is pending as one group commit
// (Journal.AppendBatch), so the bridge must hold a burst for the length of one
// flush: on a host whose disk takes 90 ms per fsync (otakunesia, 2026-11-14),
// 64 slots flushed one event at a time admitted about 11 events/s and dropped
// thousands of events overnight. The byte budget keeps memory bounded whatever
// the event sizes.
const (
	bridgeSlots    = 4096
	bridgeBytes    = 16 << 20
	bridgeMaxBatch = 512
	// lossWarnEvery: dropped telemetry is logged at most this often.
	lossWarnEvery = time.Minute
)

type bridgeOffer struct {
	event Envelope
	size  int64
}

// Publisher admits replayable input synchronously and offers non-replayable
// input through a bounded bridge (bridgeSlots, bridgeBytes) drained in group
// commits. Pending offers and loss accounting are volatile until their
// respective journal writes succeed.
type Publisher struct {
	journal           *Journal
	agentID, hostname string
	now               func() time.Time
	observe           func(Envelope)
	queue             chan bridgeOffer
	wake              chan struct{}
	done              chan struct{}
	mu                sync.Mutex
	stopped           bool
	pendingBytes      int64 // offered, not yet appended; under mu
	work              sync.WaitGroup
	failure           error

	dropped  atomic.Int64 // since the last warning
	lastWarn atomic.Int64 // unix nanoseconds
}

// NewPublisher requires an open journal. The caller must Stop all publishers
// before closing it. observe must return and may reenter Submit/TrySubmit, but
// must not synchronously wait for Stop (it is itself tracked work).
func NewPublisher(j *Journal, agentID, hostname string, observe func(Envelope)) *Publisher {
	p := &Publisher{journal: j, agentID: agentID, hostname: hostname, now: j.now, observe: observe, queue: make(chan bridgeOffer, bridgeSlots), wake: make(chan struct{}, 1), done: make(chan struct{})}
	p.work.Add(1)
	go p.run()
	return p
}

// Submit returns success only after durable append, including the source
// cursor. On failure replayable collectors must retain/retry their position.
func (p *Publisher) Submit(ctx context.Context, d Draft) (Envelope, error) {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return Envelope{}, ErrPublisherStopped
	}
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	e, err := NewEnvelope(p.agentID, p.hostname, d, p.now().UTC())
	if err != nil {
		return Envelope{}, err
	}
	if err := p.journal.Append(ctx, e); err != nil {
		return Envelope{}, err
	}
	p.observed(e)
	return e, nil
}

// SubmitBatch is Submit for several drafts in one group commit
// (Journal.AppendBatch). It returns the admitted envelopes, oldest first; when
// err is not nil it concerns drafts[len(admitted)], and later drafts were not
// admitted.
func (p *Publisher) SubmitBatch(ctx context.Context, drafts []Draft) ([]Envelope, error) {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return nil, ErrPublisherStopped
	}
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	at := p.now().UTC()
	events := make([]Envelope, 0, len(drafts))
	for _, d := range drafts {
		e, err := NewEnvelope(p.agentID, p.hostname, d, at)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	n, err := p.journal.AppendBatch(ctx, events)
	for _, e := range events[:n] {
		p.observed(e)
	}
	return events[:n], err
}

// TrySubmit returns nil for a volatile bridge offer, never for durability. It
// snapshots identity, collection time and cursor before offering and never
// acquires Journal.mu or writes to disk. Rejections and later append failures
// are aggregated for background durable loss accounting.
func (p *Publisher) TrySubmit(d Draft) error {
	e, err := NewEnvelope(p.agentID, p.hostname, d, p.now().UTC())
	var size int64
	if err == nil {
		size, err = p.bridgeSize(e)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return ErrPublisherStopped
	}
	if err != nil {
		p.lost(err)
		return err
	}
	if p.pendingBytes+size > bridgeBytes {
		p.lost(ErrBridgeFull)
		return ErrBridgeFull
	}
	select {
	case p.queue <- bridgeOffer{event: e, size: size}:
		p.pendingBytes += size
		return nil
	default:
		p.lost(ErrBridgeFull)
		return ErrBridgeFull
	}
}

// bridgeSize bounds retained payload before the queue and returns its encoded
// size. The first pass avoids allocating JSON proportional to an arbitrarily
// oversized input string.
func (p *Publisher) bridgeSize(e Envelope) (int64, error) {
	limit := p.journal.options.MaxEventBytes
	remaining := limit
	fields := []string{e.AgentID, e.Hostname, e.EventID, e.LogType, e.Location, e.RawMessage}
	if e.Cursor != nil {
		fields = append(fields, e.Cursor.Source, e.Cursor.Generation, e.Cursor.Identity, e.Cursor.Bookmark)
	}
	for _, s := range fields {
		if len(s) > remaining {
			return 0, ErrOversize
		}
		remaining -= len(s)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return 0, fmt.Errorf("encode bridge offer: %w", err)
	}
	if len(b) > limit || int64(len(b))+frameHeaderSize > p.journal.options.SegmentBytes-segmentHeaderSize {
		return 0, ErrOversize
	}
	return int64(len(b)), nil
}

func (p *Publisher) observed(e Envelope) {
	if p.observe != nil && e.LogType != "local_detection" {
		p.observe(e)
	}
}

func (p *Publisher) lost(err error) {
	p.journal.pendingBridgeLoss(err)
	p.warnLoss(err)
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// warnLoss logs dropped telemetry at most once per lossWarnEvery, with the
// count since the last warning: the loss counters alone left an overnight
// loss of thousands of events without a single log line.
func (p *Publisher) warnLoss(err error) {
	n := p.dropped.Add(1)
	now := p.now().UnixNano()
	last := p.lastWarn.Load()
	if now-last < int64(lossWarnEvery) || !p.lastWarn.CompareAndSwap(last, now) {
		return
	}
	p.dropped.Add(-n)
	slog.Warn("evidence: telemetry dropped", "events", n, "reason", err.Error(),
		"bridge_slots", bridgeSlots, "bridge_bytes", bridgeBytes)
}

func (p *Publisher) remember(err error) {
	if err != nil {
		p.mu.Lock()
		if p.failure == nil {
			p.failure = err
		}
		p.mu.Unlock()
	}
}

func (p *Publisher) run() {
	defer p.work.Done()
	// This worker is owned by the publisher, rather than any single Submit or
	// Stop caller. Stop joins it; its deadline cannot cancel an in-progress fsync.
	ctx := context.Background()
	batch := make([]Envelope, 0, bridgeMaxBatch)
	for {
		select {
		case o, ok := <-p.queue:
			if !ok {
				p.remember(p.journal.flushBridgeLoss(ctx))
				return
			}
			// Take what else is pending: one flush for the lot.
			batch = append(batch[:0], o.event)
			size := o.size
		drain:
			for len(batch) < bridgeMaxBatch {
				select {
				case more, ok := <-p.queue:
					if !ok {
						// Closed by Stop: append what was taken; the
						// next receive sees the close and returns.
						break drain
					}
					batch = append(batch, more.event)
					size += more.size
				default:
					break drain
				}
			}
			p.appendBatch(ctx, batch)
			p.mu.Lock()
			p.pendingBytes -= size
			p.mu.Unlock()
		case <-p.wake:
			// No self-rescheduling on failure: retain counters until a new
			// offer/loss signal or Stop, avoiding disk-failure busy loops.
			p.remember(p.journal.flushBridgeLoss(ctx))
		}
	}
}

// appendBatch admits events as one group commit. An event the journal refuses
// is counted as lost and the ones after it are tried again, so one bad event
// does not take its neighbours with it; a persistent failure (a full journal,
// a storage failure) counts each of them.
func (p *Publisher) appendBatch(ctx context.Context, events []Envelope) {
	for len(events) > 0 {
		n, err := p.journal.AppendBatch(ctx, events)
		for _, e := range events[:n] {
			p.observed(e)
		}
		if err == nil {
			return
		}
		p.remember(err)
		p.lost(err)
		if n >= len(events) {
			return
		}
		events = events[n+1:]
	}
}

// Stop closes admissions and drains accepted work. ErrPublisherRunning wraps
// ctx.Err and means appends/callbacks may still run: DO NOT close the journal;
// call Stop again to join. Any result without ErrPublisherRunning means all
// publisher work finished, even if a returned error reports loss/persistence
// failure. Observe callbacks must not call Stop synchronously.
func (p *Publisher) Stop(ctx context.Context) error {
	p.mu.Lock()
	if !p.stopped {
		p.stopped = true
		close(p.queue)
		go func() { p.work.Wait(); close(p.done) }()
	}
	p.mu.Unlock()
	select {
	case <-p.done:
		return p.failure
	default:
	}
	select {
	case <-p.done:
		return p.failure
	case <-ctx.Done():
		select {
		case <-p.done:
			return p.failure
		default:
		}
		return errors.Join(ErrPublisherRunning, ctx.Err())
	}
}
