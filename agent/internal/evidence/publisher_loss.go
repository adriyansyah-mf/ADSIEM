package evidence

import (
	"context"
	"errors"
	"sync"
)

var bridgeLossReasons = [3]string{"capacity", "oversize", "storage_failure"}

// This lock protects fixed-size counters only. Never hold it across I/O or
// callbacks. Journal.mu may acquire it; the callback path never acquires mu.
type bridgeLoss struct {
	mu        sync.Mutex
	counts    [3]int64
	saturated bool
}

func (j *Journal) pendingBridgeLoss(err error) {
	index := 2
	switch {
	case errors.Is(err, ErrFull), errors.Is(err, ErrBridgeFull):
		index = 0
	case errors.Is(err, ErrOversize):
		index = 1
	}
	j.bridgeLoss.mu.Lock()
	defer j.bridgeLoss.mu.Unlock()
	if j.bridgeLoss.counts[index] < maxCounter {
		j.bridgeLoss.counts[index]++
	} else {
		j.bridgeLoss.saturated = true
	}
}

// flushBridgeLoss publishes a bounded batch atomically with cumulative health.
// The callback can keep counting while this function waits on disk. Journal.mu
// serializes publication and subtraction against Snapshot and other flushes.
func (j *Journal) flushBridgeLoss(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.bridgeLoss.mu.Lock()
	counts := j.bridgeLoss.counts
	j.bridgeLoss.mu.Unlock()
	if counts == [3]int64{} {
		return nil
	}
	if err := j.ready(ctx); err != nil {
		return err
	}
	c := j.nextCheckpoint()
	for i, reason := range bridgeLossReasons {
		if counts[i] > maxCounter-c.Health.KnownLoss[reason] {
			return ErrInvalidControl
		}
		c.Health.KnownLoss[reason] += counts[i]
	}
	const source = "publisher_bridge"
	if _, ok := c.Health.Sources[source]; !ok && len(c.Health.Sources) >= 256 {
		return ErrInvalidControl
	}
	c.Health.Sources[source] = SourceHealth{State: "degraded", Reason: "non_replayable_loss", UpdatedAt: j.now().UTC()}
	generation := j.generation
	err := j.publish(ctx, c)
	// Cleanup failure may follow a fully committed checkpoint. Those counters
	// are already durable; retaining them would count the same loss twice.
	if err == nil || j.generation != generation {
		j.bridgeLoss.mu.Lock()
		for i, count := range counts {
			j.bridgeLoss.counts[i] -= count
		}
		j.bridgeLoss.mu.Unlock()
	}
	return err
}

// bridgeHealth is called under Journal.mu, after existing storage overlays.
func (j *Journal) bridgeHealth(h *Health) {
	j.bridgeLoss.mu.Lock()
	defer j.bridgeLoss.mu.Unlock()
	h.PendingLoss = make(map[string]int64, 3)
	for i, reason := range bridgeLossReasons {
		if count := j.bridgeLoss.counts[i]; count > 0 {
			h.PendingLoss[reason] = count
			h.LossUncertain = true
		}
	}
	if j.bridgeLoss.saturated {
		h.LossUncertain = true
		// Saturation means the exact number is unknown. Keep this overlay
		// sticky for this journal lifetime, including after counters flush.
		if !j.storageGap && h.UnknownGaps < maxCounter {
			h.UnknownGaps++
		}
	}
	if h.LossUncertain && h.Reason != "storage_failure" {
		h.State = "degraded"
		h.Reason = "loss_pending"
	}
}
