package evidence

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func (j *Journal) recover() error {
	files, err := j.inventory()
	if err != nil {
		return err
	}
	if err := j.loadCheckpoint(files); err != nil {
		return err
	}
	if err := j.selectSegments(files); err != nil {
		return err
	}
	for i := range j.segments {
		if err := j.recoverSegment(i); err != nil {
			return err
		}
	}
	if err := j.validateACKCoverage(); err != nil {
		return err
	}
	if err := j.cleanGenerations(); err != nil {
		return err
	}
	if err := j.cleanRetiredSegments(); err != nil {
		return err
	}
	if len(j.segments) == 0 {
		if segmentHeaderSize > j.options.MaxBytes-j.used {
			return ErrFull
		}
		return j.newSegment()
	}
	j.writer, err = j.dir.open(j.segments[len(j.segments)-1].name, os.O_RDWR|os.O_APPEND)
	return err
}

func (j *Journal) recoverSegment(index int) (err error) {
	s := &j.segments[index]
	var committedSize int64
	for _, captured := range j.checkpoint.Segments {
		if captured.Sequence == s.sequence {
			committedSize = captured.Size
			break
		}
	}
	f, err := j.dir.open(s.name, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	var header [segmentHeaderSize]byte
	if _, err := f.ReadAt(header[:], 0); err != nil {
		if errors.Is(err, io.EOF) && s.size < segmentHeaderSize && index == len(j.segments)-1 {
			if committedSize > 0 {
				return fmt.Errorf("incomplete committed segment header: %w", ErrCorrupt)
			}
			if err := j.repairHeader(f, *s); err != nil {
				return err
			}
			s.size = segmentHeaderSize
			return nil
		}
		return fmt.Errorf("segment header: %w: %w", ErrCorrupt, err)
	}
	if err := checkSegmentHeader(header[:], j.options.AgentID, s.sequence); err != nil {
		return err
	}
	for offset := int64(segmentHeaderSize); offset < s.size; {
		v, err := readRecord(f, offset, j.options.MaxEventBytes)
		if err != nil {
			if errors.Is(err, io.EOF) && index == len(j.segments)-1 {
				// A checkpoint commits this prefix as complete delivery state. Only
				// later appends may be repaired; truncation must retain the capture.
				if offset < committedSize {
					return fmt.Errorf("incomplete frame in committed prefix at %d: %w", offset, ErrCorrupt)
				}
				if err := j.preserveTail(f, *s, offset); err != nil {
					return err
				}
				j.used -= s.size - offset
				s.size = offset
				return nil
			}
			return fmt.Errorf("%s at %d: %w: %w", s.name, offset, ErrCorrupt, err)
		}
		switch v.kind {
		case frameEvent:
			if v.event.AgentID != j.options.AgentID {
				return ErrIdentityMismatch
			}
			if v.event.Cursor != nil && j.cursorAfterCheckpoint(s.sequence, offset) {
				j.cursors[v.event.Cursor.Source] = *v.event.Cursor
			}
		case frameBaseline:
			if j.cursorAfterCheckpoint(s.sequence, offset) {
				j.cursors[v.cursor.Source] = v.cursor
			}
		}
		offset = v.next
	}
	return nil
}

func (j *Journal) newSegment() error {
	if j.writer != nil {
		if err := j.writer.Close(); err != nil {
			j.writer = nil
			return fmt.Errorf("close segment: %w", err)
		}
		j.writer = nil
	}
	if j.sequence == ^uint64(0) {
		return ErrFull
	}
	sequence := j.sequence + 1
	name := segmentName(sequence)
	f, err := j.dir.open(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("create segment: %w", err)
	}
	j.writer = f
	if err := writeFull(f, segmentHeader(j.options.AgentID, sequence)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush segment header: %w", err)
	}
	if err := j.dir.sync(); err != nil {
		return fmt.Errorf("persist segment name: %w", err)
	}
	j.segments = append(j.segments, segment{name: name, sequence: sequence, size: segmentHeaderSize})
	j.used += segmentHeaderSize
	j.sequence = sequence
	return nil
}
