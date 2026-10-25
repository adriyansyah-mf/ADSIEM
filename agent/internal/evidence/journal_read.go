package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
)

func (j *Journal) checkDuplicate(ctx context.Context, e Envelope) error {
	if err := j.ready(ctx); err != nil {
		return err
	}
	if _, exists := j.checkpoint.States[e.EventID]; exists {
		return ErrConflict
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		return err
	}
	existing, positions, err := j.occurrences(ctx, e.EventID)
	if err != nil {
		return j.readFailed(err)
	}
	for i, p := range positions {
		if acknowledged(j.checkpoint, p) {
			return ErrConflict
		}
		previous, err := json.Marshal(existing[i])
		if err != nil {
			return err
		}
		if !bytes.Equal(previous, encoded) {
			return ErrConflict
		}
	}
	return nil
}

func (j *Journal) Peek(ctx context.Context) (Envelope, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return Envelope{}, false, os.ErrClosed
	}
	var next Envelope
	found := false
	// Resume where the last Peek stopped: everything before it was delivered
	// or parked (resetPeek undoes this when that stops being true).
	err := j.walkEventsFrom(ctx, j.peekFrom, func(e Envelope, p eventPosition) (bool, error) {
		if acknowledged(j.checkpoint, p) || j.checkpoint.States[e.EventID].State != "" {
			return false, nil
		}
		next, found = e, true
		j.peekFrom = p
		return true, nil
	})
	if err == nil && !found && len(j.segments) > 0 {
		last := j.segments[len(j.segments)-1]
		j.peekFrom = eventPosition{Sequence: last.sequence, Offset: last.size, End: last.size}
	}
	return next, found, j.readFailed(err)
}

// PeekBatch returns up to max deliverable events, oldest first, with their
// frames totalling at most maxBytes (always at least one event). Like Peek it
// consumes nothing.
func (j *Journal) PeekBatch(ctx context.Context, max int, maxBytes int64) ([]Envelope, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, os.ErrClosed
	}
	var batch []Envelope
	var size int64
	first := true
	err := j.walkEventsFrom(ctx, j.peekFrom, func(e Envelope, p eventPosition) (bool, error) {
		if acknowledged(j.checkpoint, p) || j.checkpoint.States[e.EventID].State != "" {
			return false, nil
		}
		frame := p.End - p.Offset
		if len(batch) > 0 && size+frame > maxBytes {
			return true, nil
		}
		if first {
			j.peekFrom, first = p, false
		}
		batch, size = append(batch, e), size+frame
		return len(batch) >= max, nil
	})
	if err == nil && len(batch) == 0 && len(j.segments) > 0 {
		last := j.segments[len(j.segments)-1]
		j.peekFrom = eventPosition{Sequence: last.sequence, Offset: last.size, End: last.size}
	}
	return batch, j.readFailed(err)
}

// resetPeek makes the next Peek start from the oldest retained record.
func (j *Journal) resetPeek() { j.peekFrom = eventPosition{} }
