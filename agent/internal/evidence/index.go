package evidence

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
)

// The journal keeps an in-memory index from event ID to the positions of its
// retained occurrences, so per-event operations (duplicate check, attempt,
// acknowledgement, hold/quarantine, operator resolve) read only that event's
// records instead of scanning the journal. Without it each of them was
// proportional to the backlog and draining a backlog was quadratic. The index
// costs memory proportional to retained events (16-byte key plus a 12-byte
// position: 42-67 B per event with map overhead, BenchmarkIndexMemory); it is
// rebuilt at open and pruned when compaction deletes segments.

type eventKey [16]byte

// packedPosition is an eventPosition in 12 bytes: what nearly every retained
// event needs, since sequences and segment offsets stay far below 2^32.
type packedPosition struct{ sequence, offset, end uint32 }

func pack(p eventPosition) (packedPosition, bool) {
	if p.Sequence > math.MaxUint32 || p.Offset < 0 || p.End > math.MaxUint32 || p.Offset > p.End {
		return packedPosition{}, false
	}
	return packedPosition{uint32(p.Sequence), uint32(p.Offset), uint32(p.End)}, true
}

func (p packedPosition) unpack() eventPosition {
	return eventPosition{Sequence: uint64(p.sequence), Offset: int64(p.offset), End: int64(p.end)}
}

// eventIndex maps event IDs to retained occurrences: the oldest one packed
// when it fits, every other one (duplicates, which are rare, or a position
// beyond 32 bits) in wide. A key's packed occurrence is always older than its
// wide ones, because packing is tried only while the key has none.
type eventIndex struct {
	packed map[eventKey]packedPosition
	wide   map[eventKey][]eventPosition
}

func newEventIndex() eventIndex {
	return eventIndex{packed: map[eventKey]packedPosition{}, wide: map[eventKey][]eventPosition{}}
}

// Len is the number of indexed event IDs.
func (x eventIndex) Len() int {
	n := len(x.packed)
	for k := range x.wide {
		if _, ok := x.packed[k]; !ok {
			n++
		}
	}
	return n
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
	j.index.add(k, p)
}

func (x eventIndex) add(k eventKey, p eventPosition) {
	_, hasPacked := x.packed[k]
	_, hasWide := x.wide[k]
	if !hasPacked && !hasWide {
		if pp, fits := pack(p); fits {
			x.packed[k] = pp
			return
		}
	}
	x.wide[k] = append(x.wide[k], p)
}

func (x eventIndex) get(k eventKey) []eventPosition {
	var ps []eventPosition
	if pp, ok := x.packed[k]; ok {
		ps = append(ps, pp.unpack())
	}
	return append(ps, x.wide[k]...)
}

// positions returns every retained occurrence of eventID, oldest first.
func (j *Journal) positions(eventID string) []eventPosition {
	k, ok := keyOf(eventID)
	if !ok {
		return nil
	}
	return j.index.get(k)
}

// rebuildIndex indexes every retained event (open, after recovery).
func (j *Journal) rebuildIndex(ctx context.Context) error {
	j.index = newEventIndex()
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
	for k, pp := range j.index.packed {
		if !retained[uint64(pp.sequence)] {
			delete(j.index.packed, k)
		}
	}
	for k, ps := range j.index.wide {
		var kept []eventPosition
		for _, p := range ps {
			if retained[p.Sequence] {
				kept = append(kept, p)
			}
		}
		if len(kept) == 0 {
			delete(j.index.wide, k)
			continue
		}
		// Keep the invariant: the oldest occurrence packed if the key has none.
		if _, ok := j.index.packed[k]; !ok {
			if pp, fits := pack(kept[0]); fits {
				j.index.packed[k], kept = pp, kept[1:]
			}
		}
		if len(kept) == 0 {
			delete(j.index.wide, k)
		} else {
			j.index.wide[k] = kept
		}
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
