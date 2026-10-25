package evidence

import (
	"fmt"
	"sort"
)

// selectSegments applies the committed retained set, then admits contiguous
// rotations created after that checkpoint's independent sequence high-water.
func (j *Journal) selectSegments(files map[string]int64) error {
	selected := map[uint64]checkpointSegment{}
	for _, s := range j.checkpoint.Segments {
		selected[s.Sequence] = s
		if size, ok := files[segmentName(s.Sequence)]; !ok || size < s.Size {
			return fmt.Errorf("missing committed segment %d: %w", s.Sequence, ErrCorrupt)
		}
	}
	j.sequence = j.checkpoint.HighSequence
	var sequences []uint64
	for name := range files {
		if sequence, ok := parseGeneration(name, "segment"); ok {
			if _, retained := selected[sequence]; retained || sequence > j.checkpoint.HighSequence {
				sequences = append(sequences, sequence)
			}
		}
	}
	sort.Slice(sequences, func(a, b int) bool { return sequences[a] < sequences[b] })
	tail := j.checkpoint.HighSequence
	for _, sequence := range sequences {
		if sequence > j.checkpoint.HighSequence {
			if sequence != tail+1 {
				return fmt.Errorf("segment sequence: %w", ErrCorrupt)
			}
			tail = sequence
		}
		name := segmentName(sequence)
		if files[name] > j.options.SegmentBytes {
			return fmt.Errorf("segment size: %w", ErrCorrupt)
		}
		j.segments = append(j.segments, segment{name: name, sequence: sequence, size: files[name]})
		if sequence > j.sequence {
			j.sequence = sequence
		}
	}
	return nil
}

func (j *Journal) cursorAfterCheckpoint(sequence uint64, offset int64) bool {
	if sequence > j.checkpoint.HighSequence {
		return true
	}
	for _, s := range j.checkpoint.Segments {
		if s.Sequence == sequence {
			return offset >= s.Size
		}
	}
	return false
}

func (j *Journal) cleanRetiredSegments() error {
	names, err := j.dir.names()
	if err != nil {
		return err
	}
	retained := map[uint64]bool{}
	for _, s := range j.segments {
		retained[s.sequence] = true
	}
	for _, name := range names {
		sequence, ok := parseGeneration(name, "segment")
		if ok && sequence <= j.checkpoint.HighSequence && !retained[sequence] {
			if err := j.removeStateFile(name); err != nil {
				return err
			}
		}
	}
	return nil
}
