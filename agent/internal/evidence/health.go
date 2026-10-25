package evidence

import (
	"context"
	"math"
	"time"
)

const maxCounter = int64(math.MaxInt64)

type SourceHealth struct {
	State     string    `json:"state"`
	Reason    string    `json:"reason"`
	UpdatedAt time.Time `json:"updated_at"`
}

type healthTotals struct {
	LastReceiptAt                           *time.Time
	Retries, Quarantined, Held, UnknownGaps int64
	KnownLoss                               map[string]int64
	Sources                                 map[string]SourceHealth
}

// Health counters are cumulative. Queue fields measure retained non-ACK payload,
// including held/quarantined evidence; those payloads still occupy the budget.
type Health struct {
	Version        int                     `json:"version"`
	State          string                  `json:"state"`
	Reason         string                  `json:"reason"`
	QueuedEvents   int64                   `json:"queued_events"`
	QueuedBytes    int64                   `json:"queued_bytes"`
	OldestQueuedAt *time.Time              `json:"oldest_queued_at"`
	LastReceiptAt  *time.Time              `json:"last_receipt_at"`
	Retries        int64                   `json:"retries"`
	Quarantined    int64                   `json:"quarantined"`
	Held           int64                   `json:"held"`
	KnownLoss      map[string]int64        `json:"known_loss"`
	UnknownGaps    int64                   `json:"unknown_gaps"`
	Sources        map[string]SourceHealth `json:"sources"`
	// PendingLoss is volatile accounting, separate from durable KnownLoss.
	PendingLoss   map[string]int64 `json:"pending_loss"`
	LossUncertain bool             `json:"loss_uncertain"`
	// IndexedEvents is the in-memory index size (retained event IDs, delivered
	// or not, until compaction); about 45-70 bytes of RAM each.
	IndexedEvents int64 `json:"indexed_events"`
}

func cloneTotals(h healthTotals) healthTotals {
	c := h
	c.KnownLoss = make(map[string]int64, len(h.KnownLoss))
	for key, value := range h.KnownLoss {
		c.KnownLoss[key] = value
	}
	c.Sources = make(map[string]SourceHealth, len(h.Sources))
	for key, value := range h.Sources {
		c.Sources[key] = value
	}
	if h.LastReceiptAt != nil {
		at := *h.LastReceiptAt
		c.LastReceiptAt = &at
	}
	return c
}

func lossReason(reason string) bool {
	switch reason {
	case "capacity", "oversize", "source_failure", "storage_failure", "rotation_gap", "legacy_import":
		return true
	default:
		return false
	}
}

// RecordLoss records a bounded reason counter and, when requested, one unknown
// gap. A failed persistence returns an error and exposes degraded process health.
func (j *Journal) RecordLoss(ctx context.Context, source, reason string, known int64, unknown bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if !boundedText(source, 256) || !lossReason(reason) || known < 0 {
		return ErrInvalidControl
	}
	c := j.nextCheckpoint()
	if known > maxCounter-c.Health.KnownLoss[reason] || (unknown && c.Health.UnknownGaps == maxCounter) {
		return ErrInvalidControl
	}
	c.Health.KnownLoss[reason] += known
	if unknown {
		c.Health.UnknownGaps++
	}
	if _, ok := c.Health.Sources[source]; !ok && len(c.Health.Sources) >= 256 {
		return ErrInvalidControl
	}
	c.Health.Sources[source] = SourceHealth{State: "degraded", Reason: reason, UpdatedAt: j.now().UTC()}
	return j.publish(ctx, c)
}

func (j *Journal) SetSourceState(ctx context.Context, source, state, reason string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if !boundedText(source, 256) || !boundedText(reason, 256) {
		return ErrInvalidControl
	}
	switch state {
	case "healthy", "degraded", "paused", "unavailable":
	default:
		return ErrInvalidControl
	}
	c := j.nextCheckpoint()
	if _, ok := c.Health.Sources[source]; !ok && len(c.Health.Sources) >= 256 {
		return ErrInvalidControl
	}
	c.Health.Sources[source] = SourceHealth{State: state, Reason: reason, UpdatedAt: j.now().UTC()}
	return j.publish(ctx, c)
}

// Snapshot returns detached values and does not clear counters on heartbeat.
// Reading failure is visible even when no durable counter can be written.
func (j *Journal) Snapshot() Health {
	j.mu.Lock()
	defer j.mu.Unlock()
	totals := cloneTotals(j.checkpoint.Health)
	h := Health{Version: 1, State: "healthy", Reason: "", LastReceiptAt: totals.LastReceiptAt, Retries: totals.Retries, Quarantined: totals.Quarantined, Held: totals.Held, KnownLoss: totals.KnownLoss, UnknownGaps: totals.UnknownGaps, Sources: totals.Sources}
	for _, source := range h.Sources {
		if source.State != "healthy" {
			h.State = "degraded"
			h.Reason = "source_failure"
		}
	}
	for _, state := range j.checkpoint.States {
		switch state.State {
		case "held":
			h.State = "degraded"
			h.Reason = "held"
		case "quarantined":
			if h.Reason != "held" {
				h.State = "degraded"
				h.Reason = "quarantined"
			}
		case "":
		}
	}
	// Counted from the index, not by reading the journal (that held the lock for
	// seconds on a large backlog). Only the records collected in the oldest
	// second are read, for the exact OldestQueuedAt.
	h.IndexedEvents = int64(j.index.Len())
	oldest := int64(math.MaxInt64)
	var candidates []eventPosition
	j.index.each(func(p indexedPosition) {
		if acknowledged(j.checkpoint, p.eventPosition) {
			return
		}
		h.QueuedEvents++
		h.QueuedBytes += p.End - p.Offset
		switch {
		case p.collected < oldest:
			oldest, candidates = p.collected, append(candidates[:0], p.eventPosition)
		case p.collected == oldest:
			candidates = append(candidates, p.eventPosition)
		}
	})
	if err := j.readEach(candidates, func(e Envelope) {
		if h.OldestQueuedAt == nil || e.CollectedAt.Before(*h.OldestQueuedAt) {
			at := e.CollectedAt
			h.OldestQueuedAt = &at
		}
	}); err != nil {
		j.storageGap = true
	}
	if j.storageGap {
		h.State = "degraded"
		h.Reason = "storage_failure"
		if h.UnknownGaps < maxCounter {
			h.UnknownGaps++
		}
	} else if j.capacity {
		h.State = "degraded"
		h.Reason = "capacity"
	}
	j.bridgeHealth(&h)
	return h
}
