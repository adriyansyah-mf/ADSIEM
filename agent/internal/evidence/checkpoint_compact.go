package evidence

import (
	"context"
	"errors"
	"os"
)

// Compact commits the retained segment set and cursor snapshot before removing
// any payload. It never copies a backlog or reclaims non-receipt terminal states.
func (j *Journal) Compact(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	c := j.nextCheckpoint()
	pending := map[uint64]bool{}
	err := j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		if !acknowledged(c, p) {
			pending[p.Sequence] = true
		}
		return false, nil
	})
	if err != nil {
		return j.readFailed(err)
	}
	var retained []segment
	c.Segments = nil
	for _, s := range j.segments {
		if pending[s.sequence] {
			retained = append(retained, s)
			c.Segments = append(c.Segments, checkpointSegment{s.sequence, s.size})
		} else {
			delete(c.ACKs, s.sequence)
		}
	}
	previous := j.segments
	j.segments = retained
	generation := j.checkpoint.Generation
	if err := j.publish(ctx, c); err != nil {
		if j.checkpoint.Generation == generation {
			j.segments = previous
		}
		return err
	}
	j.pruneIndex()
	j.resetPeek()
	// Windows denies deletion sharing on live handles. Close only after a
	// successful publication, so quota refusal leaves the healthy writer usable.
	if j.writer != nil {
		if err := j.writer.Close(); err != nil {
			return j.storageFailed(err)
		}
		j.writer = nil
	}
	if err := j.cleanRetiredSegments(); err != nil {
		return j.storageFailed(err)
	}
	if len(j.segments) == 0 {
		if segmentHeaderSize > j.options.MaxBytes-j.used {
			return j.storageFailed(ErrFull)
		}
		if err := j.newSegment(); err != nil {
			return j.storageFailed(err)
		}
		return nil
	}
	j.writer, err = j.dir.open(j.segments[len(j.segments)-1].name, os.O_RDWR|os.O_APPEND)
	if err != nil {
		return j.storageFailed(err)
	}
	return nil
}

func (j *Journal) validateACKCoverage() error {
	segments := map[uint64]int64{}
	for _, s := range j.checkpoint.Segments {
		segments[s.Sequence] = s.Size
	}
	starts := map[eventPosition]bool{}
	ends := map[eventPosition]bool{}
	for sequence, ranges := range j.checkpoint.ACKs {
		size, ok := segments[sequence]
		if !ok {
			return ErrCorrupt
		}
		last := int64(segmentHeaderSize - 1)
		for _, r := range ranges {
			if r.Start <= last || r.End <= r.Start || r.End > size {
				return ErrCorrupt
			}
			last = r.End
			starts[eventPosition{Sequence: sequence, Offset: r.Start}] = false
			ends[eventPosition{Sequence: sequence, End: r.End}] = false
		}
	}
	states := map[string]bool{}
	for id := range j.checkpoint.States {
		if err := ValidateAgentID(id); err != nil {
			return ErrCorrupt
		}
		states[id] = false
	}
	err := j.walkEvents(context.TODO(), func(e Envelope, p eventPosition) (bool, error) {
		start := eventPosition{Sequence: p.Sequence, Offset: p.Offset}
		if _, ok := starts[start]; ok {
			starts[start] = true
		}
		end := eventPosition{Sequence: p.Sequence, End: p.End}
		if _, ok := ends[end]; ok {
			ends[end] = true
		}
		if _, ok := states[e.EventID]; ok {
			if acknowledged(j.checkpoint, p) {
				return false, ErrCorrupt
			}
			states[e.EventID] = true
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	for _, found := range starts {
		if !found {
			return ErrCorrupt
		}
	}
	for _, found := range ends {
		if !found {
			return ErrCorrupt
		}
	}
	for _, found := range states {
		if !found {
			return ErrCorrupt
		}
	}
	return nil
}

// Keep cancellation a caller condition, never a storage uncertainty interval.
func controlReadError(err error) bool {
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, ErrConflict)
}
