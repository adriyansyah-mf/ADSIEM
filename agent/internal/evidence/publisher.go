package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrBridgeFull       = errors.New("evidence: non-replayable bridge full")
	ErrPublisherStopped = errors.New("evidence: publisher admissions stopped")
	ErrPublisherRunning = errors.New("evidence: publisher still running; keep journal open and retry Stop")
)

// Publisher admits replayable input synchronously and offers non-replayable
// input through 64 pending slots plus one active append. Pending offers and loss
// accounting are volatile until their respective journal writes succeed.
type Publisher struct {
	journal           *Journal
	agentID, hostname string
	now               func() time.Time
	observe           func(Envelope)
	queue             chan Envelope
	wake              chan struct{}
	done              chan struct{}
	mu                sync.Mutex
	stopped           bool
	work              sync.WaitGroup
	failure           error
}

// NewPublisher requires an open journal. The caller must Stop all publishers
// before closing it. observe must return and may reenter Submit/TrySubmit, but
// must not synchronously wait for Stop (it is itself tracked work).
func NewPublisher(j *Journal, agentID, hostname string, observe func(Envelope)) *Publisher {
	p := &Publisher{journal: j, agentID: agentID, hostname: hostname, now: j.now, observe: observe, queue: make(chan Envelope, 64), wake: make(chan struct{}, 1), done: make(chan struct{})}
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

// TrySubmit returns nil for a volatile bridge offer, never for durability. It
// snapshots identity, collection time and cursor before offering and never
// acquires Journal.mu or writes to disk. Rejections and later append failures
// are aggregated for background durable loss accounting.
func (p *Publisher) TrySubmit(d Draft) error {
	e, err := NewEnvelope(p.agentID, p.hostname, d, p.now().UTC())
	if err == nil {
		err = p.bridgeSize(e)
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
	select {
	case p.queue <- e:
		return nil
	default:
		p.lost(ErrBridgeFull)
		return ErrBridgeFull
	}
}

// bridgeSize bounds retained payload before the queue. The first pass avoids
// allocating JSON proportional to an arbitrarily oversized input string.
func (p *Publisher) bridgeSize(e Envelope) error {
	limit := p.journal.options.MaxEventBytes
	remaining := limit
	fields := []string{e.AgentID, e.Hostname, e.EventID, e.LogType, e.Location, e.RawMessage}
	if e.Cursor != nil {
		fields = append(fields, e.Cursor.Source, e.Cursor.Generation, e.Cursor.Identity, e.Cursor.Bookmark)
	}
	for _, s := range fields {
		if len(s) > remaining {
			return ErrOversize
		}
		remaining -= len(s)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode bridge offer: %w", err)
	}
	if len(b) > limit || int64(len(b))+frameHeaderSize > p.journal.options.SegmentBytes-segmentHeaderSize {
		return ErrOversize
	}
	return nil
}

func (p *Publisher) observed(e Envelope) {
	if p.observe != nil && e.LogType != "local_detection" {
		p.observe(e)
	}
}

func (p *Publisher) lost(err error) {
	p.journal.pendingBridgeLoss(err)
	select {
	case p.wake <- struct{}{}:
	default:
	}
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
	for {
		select {
		case e, ok := <-p.queue:
			if !ok {
				p.remember(p.journal.flushBridgeLoss(ctx))
				return
			}
			if err := p.journal.Append(ctx, e); err != nil {
				p.remember(err)
				p.lost(err)
			} else {
				p.observed(e)
			}
		case <-p.wake:
			// No self-rescheduling on failure: retain counters until a new
			// offer/loss signal or Stop, avoiding disk-failure busy loops.
			p.remember(p.journal.flushBridgeLoss(ctx))
		}
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
