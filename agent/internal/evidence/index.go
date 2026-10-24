package evidence

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// The journal keeps an in-memory index from event ID to the positions of its
// retained occurrences, so per-event operations (duplicate check, attempt,
// acknowledgement, hold/quarantine, operator resolve) read only that event's
// records instead of scanning the journal. Without it each of them was
// proportional to the backlog and draining a backlog was quadratic. The index
// costs memory proportional to retained events (16-byte key plus position,
// see docs/operations/agent-evidence-validation.md for measurements); it is
// rebuilt at open and pruned when compaction deletes segments.

type eventKey [16]byte

// indexEntry holds the first occurrence inline; duplicates are rare.
type indexEntry struct {
	first eventPosition
	more  []eventPosition
}

func keyOf(eventID string) (eventKey, bool) {
	var k eventKey
	if ValidateAgentID(eventID) != nil { // the same UUID rules as event IDs
		return k, false
	}
	compact := eventID[:8] + eventID[9:13] + eventID[14:18] + eventID[19:23] + eventID[24:]
	if _, err := hex.Decode(k[:], []byte(compact)); err != nil {
		return k, false
	}
	return k, true
}

func (j *Journal) indexAdd(eventID string, p eventPosition) {
	k, ok := keyOf(eventID)
	if !ok {
		return
	}
	if e, exists := j.index[k]; exists {
		e.more = append(e.more, p)
		j.index[k] = e
		return
	}
	j.index[k] = indexEntry{first: p}
}

// positions returns every retained occurrence of eventID, oldest first.
func (j *Journal) positions(eventID string) []eventPosition {
	k, ok := keyOf(eventID)
	if !ok {
		return nil
	}
	e, exists := j.index[k]
	if !exists {
		return nil
	}
	return append([]eventPosition{e.first}, e.more...)
}

// rebuildIndex indexes every retained event (open, after recovery).
func (j *Journal) rebuildIndex(ctx context.Context) error {
	j.index = map[eventKey]indexEntry{}
	return j.walkEvents(ctx, func(e Envelope, p eventPosition) (bool, error) {
		j.indexAdd(e.EventID, p)
		return false, nil
	})
}

// pruneIndex drops positions in segments that are no longer retained.
func (j *Journal) pruneIndex() {
	retained := make(map[uint64]bool, len(j.segments))
	for _, s := range j.segments {
		retained[s.sequence] = true
	}
	for k, e := range j.index {
		var kept []eventPosition
		for _, p := range append([]eventPosition{e.first}, e.more...) {
			if retained[p.Sequence] {
				kept = append(kept, p)
			}
		}
		if len(kept) == 0 {
			delete(j.index, k)
			continue
		}
		j.index[k] = indexEntry{first: kept[0], more: kept[1:]}
	}
}

// readAt decodes the event record at p.
func (j *Journal) readAt(p eventPosition) (Envelope, error) {
	for _, s := range j.segments {
		if s.sequence != p.Sequence {
			continue
		}
		f, err := j.dir.open(s.name, os.O_RDONLY)
		if err != nil {
			return Envelope{}, err
		}
		v, readErr := readRecord(io.NewSectionReader(f, 0, s.size), p.Offset, j.options.MaxEventBytes)
		if err := errors.Join(readErr, f.Close()); err != nil {
			return Envelope{}, err
		}
		if v.kind != frameEvent || v.next != p.End {
			return Envelope{}, ErrCorrupt
		}
		return v.event, nil
	}
	return Envelope{}, ErrCorrupt // indexed position in a segment that is gone
}

// occurrences reads every retained occurrence of eventID. Like the scans it
// replaces, it observes cancellation before each read and once at the end,
// so a canceled caller stops before publishing anything.
func (j *Journal) occurrences(ctx context.Context, eventID string) ([]Envelope, []eventPosition, error) {
	ps := j.positions(eventID)
	events := make([]Envelope, 0, len(ps))
	for _, p := range ps {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		e, err := j.readAt(p)
		if err != nil {
			return nil, nil, err
		}
		events = append(events, e)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return events, ps, nil
}

// walkEventsFrom is walkEvents starting at from (a record boundary in a
// retained segment, or past the end of the last one).
func (j *Journal) walkEventsFrom(ctx context.Context, from eventPosition, visit func(Envelope, eventPosition) (bool, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.closed {
		return os.ErrClosed
	}
	for _, s := range j.segments {
		if s.sequence < from.Sequence {
			continue
		}
		start := int64(segmentHeaderSize)
		if s.sequence == from.Sequence && from.Offset > start {
			start = from.Offset
		}
		if start >= s.size {
			continue
		}
		f, err := j.dir.open(s.name, os.O_RDONLY)
		if err != nil {
			return err
		}
		scanner := segmentScanner{file: f, segment: s, maxEventBytes: j.options.MaxEventBytes, start: start}
		stop, readErr := scanner.walk(ctx, visit)
		if err := errors.Join(readErr, f.Close()); err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return nil
}
