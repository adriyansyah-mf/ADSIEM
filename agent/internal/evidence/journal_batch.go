package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
)

type preparedEvent struct {
	event Envelope
	frame []byte
	size  int64
}

// AppendBatch is Append for several events sharing flushes (group commit):
// every frame of the batch is written, then the segment is flushed once, and
// only then are the events admitted. A batch that crosses a segment boundary
// flushes the full segment before starting the next one. Durability per event
// is the same as Append's; what changes is one flush for many events.
//
// It returns how many leading events were admitted. When err is not nil it
// concerns events[n]: an invalid, conflicting or oversized event, a full
// journal, or a storage failure. Events after n were not admitted.
func (j *Journal) AppendBatch(ctx context.Context, events []Envelope) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	prepared := make([]preparedEvent, 0, len(events))
	inBatch := make(map[string][]byte, len(events))
	for _, e := range events {
		p, err := j.prepare(ctx, e, inBatch)
		if err != nil {
			n, admitErr := j.admitEvents(ctx, prepared)
			if admitErr != nil {
				return n, admitErr
			}
			return n, err
		}
		prepared = append(prepared, p)
	}
	return j.admitEvents(ctx, prepared)
}

// prepare validates and encodes one event, including against earlier events
// of the same batch (an identical repeat is allowed, as for Append).
func (j *Journal) prepare(ctx context.Context, e Envelope, inBatch map[string][]byte) (preparedEvent, error) {
	if e.AgentID != j.options.AgentID {
		return preparedEvent{}, ErrIdentityMismatch
	}
	if e.ProtocolVersion != 2 {
		return preparedEvent{}, fmt.Errorf("event protocol: %w", ErrCorrupt)
	}
	if err := ValidateAgentID(e.EventID); err != nil {
		return preparedEvent{}, err
	}
	if e.Cursor != nil {
		if e.Cursor.Source == "" {
			return preparedEvent{}, ErrInvalidControl
		}
		c := *e.Cursor
		e.Cursor = &c
	}
	if err := j.checkDuplicate(ctx, e); err != nil {
		return preparedEvent{}, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return preparedEvent{}, fmt.Errorf("encode event: %w", err)
	}
	if prior, seen := inBatch[e.EventID]; seen && !bytes.Equal(prior, b) {
		return preparedEvent{}, ErrConflict
	}
	inBatch[e.EventID] = b
	return preparedEvent{event: e, frame: encodeFrame(frameEvent, b), size: int64(frameHeaderSize) + int64(len(b))}, nil
}

// admitEvents writes prepared events and flushes them, segment by segment.
// Caller holds j.mu.
func (j *Journal) admitEvents(ctx context.Context, events []preparedEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if j.closed {
		return 0, os.ErrClosed
	}
	if j.poison != nil {
		return 0, fmt.Errorf("journal requires reopen: %w", j.poison)
	}
	admitted := 0
	var pending []preparedEvent // written to the current segment, not yet flushed
	var pendingBytes int64
	// flush makes the pending frames durable and only then admits them.
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := j.writer.Sync(); err != nil {
			return j.storageFailed(fmt.Errorf("flush record: %w", err))
		}
		seg := &j.segments[len(j.segments)-1]
		for _, p := range pending {
			start := seg.size
			seg.size += p.size
			j.used += p.size
			j.indexAdd(p.event, eventPosition{Sequence: seg.sequence, Offset: start, End: seg.size})
			if p.event.Cursor != nil {
				j.cursors[p.event.Cursor.Source] = *p.event.Cursor
			}
		}
		admitted += len(pending)
		pending, pendingBytes = pending[:0], 0
		j.capacity = false
		return nil
	}
	limit := j.options.MaxBytes - j.options.ReservedBytes
	for _, p := range events {
		if p.size-frameHeaderSize > int64(j.options.MaxEventBytes) || p.size > j.options.SegmentBytes-segmentHeaderSize {
			if err := flush(); err != nil {
				return admitted, err
			}
			return admitted, ErrOversize
		}
		rotate := len(j.segments) == 0 || j.segments[len(j.segments)-1].size+pendingBytes+p.size > j.options.SegmentBytes
		additional := p.size
		if rotate {
			additional += segmentHeaderSize
		}
		if additional > limit-j.used-pendingBytes {
			if err := flush(); err != nil {
				return admitted, err
			}
			j.capacity = true
			return admitted, ErrFull
		}
		if rotate {
			if err := flush(); err != nil { // the full segment is durable before the next starts
				return admitted, err
			}
			if err := j.newSegment(); err != nil {
				return admitted, j.storageFailed(err)
			}
		}
		if err := writeFull(j.writer, p.frame); err != nil {
			return admitted, j.storageFailed(err)
		}
		pending = append(pending, p)
		pendingBytes += p.size
	}
	if err := flush(); err != nil {
		return admitted, err
	}
	return admitted, nil
}
