package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

var (
	ErrUnknownEvent   = errors.New("evidence: event is not retained")
	ErrTerminal       = errors.New("evidence: event is held or quarantined")
	ErrConflict       = errors.New("evidence: conflicting event identity or state")
	ErrInvalidControl = errors.New("evidence: invalid control value")
)

type ackSpan struct{ Start, End int64 }
type checkpointSegment struct {
	Sequence uint64
	Size     int64
}
type eventState struct {
	FirstAttempt time.Time `json:"first_attempt,omitempty"`
	State        string    `json:"state,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}

// A checkpoint contains control metadata only, never event payloads. ACK spans
// merge adjacent frames and therefore compact even inside a partial segment.
type checkpoint struct {
	Version      int
	AgentID      string
	Generation   uint64
	HighSequence uint64
	Segments     []checkpointSegment
	Cursors      map[string]Cursor
	ACKs         map[uint64][]ackSpan
	States       map[string]eventState
	Health       healthTotals
}

func emptyCheckpoint(agentID string) checkpoint {
	return checkpoint{Version: 1, AgentID: agentID, Cursors: map[string]Cursor{}, ACKs: map[uint64][]ackSpan{}, States: map[string]eventState{}, Health: healthTotals{KnownLoss: map[string]int64{}, Sources: map[string]SourceHealth{}}}
}

func (j *Journal) nextCheckpoint() checkpoint {
	c := j.checkpoint
	c.Cursors = make(map[string]Cursor, len(j.cursors))
	for key, value := range j.cursors {
		c.Cursors[key] = value
	}
	c.ACKs = make(map[uint64][]ackSpan, len(j.checkpoint.ACKs))
	for key, value := range j.checkpoint.ACKs {
		c.ACKs[key] = append([]ackSpan(nil), value...)
	}
	c.States = make(map[string]eventState, len(j.checkpoint.States))
	for key, value := range j.checkpoint.States {
		c.States[key] = value
	}
	c.Health = cloneTotals(c.Health)
	c.Segments = nil
	for _, s := range j.segments {
		c.Segments = append(c.Segments, checkpointSegment{Sequence: s.sequence, Size: s.size})
	}
	c.HighSequence = j.sequence
	return c
}

type eventPosition struct {
	Sequence    uint64
	Offset, End int64
}

func acknowledged(c checkpoint, p eventPosition) bool {
	for _, r := range c.ACKs[p.Sequence] {
		if p.Offset >= r.Start && p.End <= r.End {
			return true
		}
	}
	return false
}

func addACK(c *checkpoint, p eventPosition) {
	ranges := append(c.ACKs[p.Sequence], ackSpan{p.Offset, p.End})
	sort.Slice(ranges, func(a, b int) bool { return ranges[a].Start < ranges[b].Start })
	merged := ranges[:0]
	for _, r := range ranges {
		if len(merged) > 0 && r.Start <= merged[len(merged)-1].End {
			if r.End > merged[len(merged)-1].End {
				merged[len(merged)-1].End = r.End
			}
			continue
		}
		merged = append(merged, r)
	}
	c.ACKs[p.Sequence] = merged
}

// walkEvents bounds payload memory to one MaxEventBytes frame. Control lookup
// deliberately trades scan time for avoiding a backlog-sized event index.
func (j *Journal) walkEvents(ctx context.Context, visit func(Envelope, eventPosition) (bool, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.closed {
		return os.ErrClosed
	}
	for _, s := range j.segments {
		f, err := j.dir.open(s.name, os.O_RDONLY)
		if err != nil {
			return err
		}
		scanner := segmentScanner{file: f, segment: s, maxEventBytes: j.options.MaxEventBytes}
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

type segmentScanner struct {
	file          *os.File
	segment       segment
	maxEventBytes int
}

func (s segmentScanner) walk(ctx context.Context, visit func(Envelope, eventPosition) (bool, error)) (bool, error) {
	for offset := int64(segmentHeaderSize); offset < s.segment.size; {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		v, err := readRecord(io.NewSectionReader(s.file, 0, s.segment.size), offset, s.maxEventBytes)
		if err != nil {
			return false, err
		}
		if v.kind == frameEvent {
			stop, err := visit(v.event, eventPosition{s.segment.sequence, offset, v.next})
			if stop || err != nil {
				return stop, err
			}
		}
		offset = v.next
	}
	return false, nil
}

func (j *Journal) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.closed {
		return os.ErrClosed
	}
	if j.poison != nil {
		return fmt.Errorf("journal requires reopen: %w", j.poison)
	}
	return nil
}

func (j *Journal) storageFailed(err error) error {
	j.poison = err
	j.storageGap = true
	return err
}

func (j *Journal) readFailed(err error) error {
	if controlReadError(err) {
		return j.storageFailed(err)
	}
	return err
}

func segmentName(sequence uint64) string { return fmt.Sprintf("segment-%020d.evj", sequence) }
