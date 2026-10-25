package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// SalvageReport says what Salvage read, kept and could not read.
type SalvageReport struct {
	Source, Target string
	// CheckpointUsable: delivery state (receipts, holds, first attempts, the
	// cursors it committed) was read. Without it every readable event is
	// imported again and the server answers delivered ones as duplicates.
	CheckpointUsable bool
	Segments         int
	Readable         int // event records that decoded
	Delivered        int // of those, already acknowledged: not imported
	Imported         int
	Conflicts        int // one event ID with two different contents: the first is kept
	// UnreadableRegions are damaged spans skipped up to the next intact
	// record; each is counted as one unknown gap in the new journal.
	UnreadableRegions int
	UnreadableBytes   int64
	TornTailBytes     int64 // an incomplete final record: never admitted, not a loss
	Cursors           int
	Problems          []string
}

type salvaged struct {
	event Envelope
	at    eventPosition
}

// Salvage copies the readable, undelivered evidence of the journal in
// damaged.Dir, which Open refuses, into a new journal at target, so collection
// can restart without losing what survived or skipping what files still hold.
//
// The damaged journal is only read, under its lock (the agent must be
// stopped). Records are scanned frame by frame; a damaged span is skipped up
// to the next record whose header and payload checksums both match. The new
// journal gets every intact undelivered event with its original identity and
// collection time, the latest committed cursor of every source (so files
// resume where they were instead of starting at their end), held and
// quarantined states, first attempts (the 30-day uncertainty window keeps
// running), and the cumulative health counters plus one unknown gap per
// unreadable span. target must not exist or be empty.
func Salvage(ctx context.Context, damaged Options, target string) (SalvageReport, error) {
	r := SalvageReport{Source: damaged.Dir, Target: target}
	if err := damaged.Validate(); err != nil {
		return r, err
	}
	if err := ValidateAgentID(damaged.AgentID); err != nil {
		return r, err
	}
	if entries, err := os.ReadDir(target); err == nil && len(entries) > 0 {
		return r, fmt.Errorf("salvage target %s is not empty", target)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return r, err
	}

	d, err := openStorageDir(damaged.Dir)
	if err != nil {
		return r, fmt.Errorf("open damaged journal: %w", err)
	}
	defer d.close()
	lock, err := d.lock()
	if err != nil {
		return r, fmt.Errorf("acquire damaged journal: %w", err)
	}
	defer lock.Close()
	src := &Journal{options: damaged, dir: d, cursors: map[string]Cursor{}, checkpoint: emptyCheckpoint(damaged.AgentID), now: time.Now}

	files, err := salvageInventory(d)
	if err != nil {
		return r, err
	}
	if err := src.loadCheckpoint(files); err != nil {
		r.Problems = append(r.Problems, fmt.Sprintf("checkpoint unreadable (%v): delivery state is unknown, every readable event is imported", err))
		src.checkpoint, src.cursors = emptyCheckpoint(damaged.AgentID), map[string]Cursor{}
	} else {
		r.CheckpointUsable = true
	}

	events, err := src.salvageSegments(ctx, files, &r)
	if err != nil {
		return r, err
	}
	if err := writeSalvage(ctx, damaged, target, src, events, &r); err != nil {
		return r, err
	}
	return r, nil
}

func salvageInventory(d *storageDir) (map[string]int64, error) {
	names, err := d.names()
	if err != nil {
		return nil, err
	}
	files := make(map[string]int64, len(names))
	for _, name := range names {
		f, err := d.open(name, os.O_RDONLY)
		if err != nil {
			return nil, err
		}
		info, statErr := f.Stat()
		if err := errors.Join(statErr, f.Close()); err != nil {
			return nil, err
		}
		files[name] = info.Size()
	}
	return files, nil
}

// salvageSegments reads every retained segment in order, resynchronizing past
// damage, and returns the undelivered events. It updates j.cursors with every
// cursor committed after the checkpoint (all of them without one).
func (j *Journal) salvageSegments(ctx context.Context, files map[string]int64, r *SalvageReport) ([]salvaged, error) {
	retained := map[uint64]bool{}
	for _, s := range j.checkpoint.Segments {
		retained[s.Sequence] = true
	}
	var sequences []uint64
	for name := range files {
		if seq, ok := parseGeneration(name, "segment"); ok {
			// Below the checkpoint's high sequence and not listed: retired, fully delivered.
			if r.CheckpointUsable && seq <= j.checkpoint.HighSequence && !retained[seq] {
				continue
			}
			sequences = append(sequences, seq)
		}
	}
	sort.Slice(sequences, func(a, b int) bool { return sequences[a] < sequences[b] })
	r.Segments = len(sequences)

	var out []salvaged
	for i, seq := range sequences {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b, err := j.readSegment(segmentName(seq))
		if err != nil {
			return nil, err
		}
		if len(b) < segmentHeaderSize || checkSegmentHeader(b[:segmentHeaderSize], j.options.AgentID, seq) != nil {
			r.UnreadableRegions++
			r.UnreadableBytes += int64(len(b))
			r.Problems = append(r.Problems, fmt.Sprintf("%s: unreadable segment header, %d bytes skipped", segmentName(seq), len(b)))
			continue
		}
		reader := bytes.NewReader(b)
		last := i == len(sequences)-1
		for offset := int64(segmentHeaderSize); offset < int64(len(b)); {
			v, err := readRecord(reader, offset, j.options.MaxEventBytes)
			if err != nil {
				next := resync(reader, b, offset+1, j.options.MaxEventBytes)
				if next < 0 && last && errors.Is(err, io.EOF) {
					r.TornTailBytes += int64(len(b)) - offset
					break
				}
				if next < 0 {
					next = int64(len(b))
				}
				r.UnreadableRegions++
				r.UnreadableBytes += next - offset
				r.Problems = append(r.Problems, fmt.Sprintf("%s: %d unreadable bytes at offset %d", segmentName(seq), next-offset, offset))
				offset = next
				continue
			}
			p := eventPosition{Sequence: seq, Offset: offset, End: v.next}
			after := !r.CheckpointUsable || j.cursorAfterCheckpoint(seq, offset)
			switch v.kind {
			case frameEvent:
				r.Readable++
				if v.event.Cursor != nil && after {
					j.cursors[v.event.Cursor.Source] = *v.event.Cursor
				}
				if r.CheckpointUsable && acknowledged(j.checkpoint, p) {
					r.Delivered++
				} else {
					out = append(out, salvaged{event: v.event, at: p})
				}
			case frameBaseline:
				if after {
					j.cursors[v.cursor.Source] = v.cursor
				}
			}
			offset = v.next
		}
	}
	return out, nil
}

func (j *Journal) readSegment(name string) (b []byte, err error) {
	f, err := j.dir.open(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return io.ReadAll(io.LimitReader(f, j.options.SegmentBytes+1))
}

// resync returns the offset of the next intact record at or after from, or -1.
func resync(reader io.ReaderAt, b []byte, from int64, maxBytes int) int64 {
	for from < int64(len(b)) {
		i := bytes.Index(b[from:], []byte("EVJR"))
		if i < 0 {
			return -1
		}
		at := from + int64(i)
		if _, err := readRecord(reader, at, maxBytes); err == nil {
			return at
		}
		from = at + 1
	}
	return -1
}

func writeSalvage(ctx context.Context, damaged Options, target string, src *Journal, events []salvaged, r *SalvageReport) (err error) {
	o := damaged
	o.Dir = target
	dst, err := Open(o)
	if err != nil {
		return fmt.Errorf("create salvage journal: %w", err)
	}
	defer func() { err = errors.Join(err, dst.Close()) }()

	imported := map[string][]byte{}
	for _, s := range events {
		encoded, err := json.Marshal(s.event)
		if err != nil {
			return err
		}
		if prior, seen := imported[s.event.EventID]; seen {
			if !bytes.Equal(prior, encoded) {
				r.Conflicts++
				r.Problems = append(r.Problems, fmt.Sprintf("event %s has two different contents: the first is kept", s.event.EventID))
			}
			continue // an identical retried append is one event
		}
		if err := dst.Append(ctx, s.event); err != nil {
			return fmt.Errorf("import event %s: %w", s.event.EventID, err)
		}
		imported[s.event.EventID] = encoded
		r.Imported++
	}

	sources := make([]string, 0, len(src.cursors))
	for source := range src.cursors {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		if err := dst.SaveBaseline(ctx, src.cursors[source]); err != nil {
			return fmt.Errorf("carry cursor %s: %w", source, err)
		}
	}
	r.Cursors = len(sources)

	for id, s := range src.checkpoint.States {
		if _, ok := imported[id]; !ok {
			continue
		}
		if !s.FirstAttempt.IsZero() {
			if err := dst.MarkAttempt(ctx, id, s.FirstAttempt); err != nil {
				return fmt.Errorf("carry first attempt of %s: %w", id, err)
			}
		}
		switch s.State {
		case "held":
			err = dst.Hold(ctx, id, s.Reason)
		case "quarantined":
			err = dst.Quarantine(ctx, id, s.Reason)
		}
		if err != nil {
			return fmt.Errorf("carry state of %s: %w", id, err)
		}
	}
	h := src.checkpoint.Health
	return dst.carryHealth(ctx, h.KnownLoss, h.UnknownGaps+int64(r.UnreadableRegions), h.Retries)
}

// carryHealth adds cumulative counters from a salvaged journal in one
// publication, so a salvage never resets loss history.
func (j *Journal) carryHealth(ctx context.Context, known map[string]int64, gaps, retries int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	c := j.nextCheckpoint()
	for reason, n := range known {
		if !lossReason(reason) || n < 0 || n > maxCounter-c.Health.KnownLoss[reason] {
			return ErrInvalidControl
		}
		c.Health.KnownLoss[reason] += n
	}
	if gaps < 0 || retries < 0 || gaps > maxCounter-c.Health.UnknownGaps || retries > maxCounter-c.Health.Retries {
		return ErrInvalidControl
	}
	c.Health.UnknownGaps += gaps
	c.Health.Retries += retries
	return j.publish(ctx, c)
}
