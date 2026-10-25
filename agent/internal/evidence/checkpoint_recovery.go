package evidence

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

func parseGeneration(name, prefix string) (uint64, bool) {
	if len(name) != len(prefix)+1+20+4 || !strings.HasPrefix(name, prefix+"-") || !strings.HasSuffix(name, ".evj") {
		return 0, false
	}
	n, err := strconv.ParseUint(name[len(prefix)+1:len(name)-4], 10, 64)
	return n, err == nil && n > 0
}

// inventory counts all retained files before cleanup, including abandoned
// generations and retired payload pending deletion. Lowered quotas fail closed.
func (j *Journal) inventory() (map[string]int64, error) {
	names, err := j.dir.names()
	if err != nil {
		return nil, err
	}
	files := make(map[string]int64, len(names))
	for _, name := range names {
		f, err := j.dir.open(name, os.O_RDONLY)
		if err != nil {
			return nil, err
		}
		info, statErr := f.Stat()
		if err := errors.Join(statErr, f.Close()); err != nil {
			return nil, err
		}
		if info.Size() > j.options.MaxBytes-j.used {
			return nil, ErrFull
		}
		j.used += info.Size()
		files[name] = info.Size()
		switch {
		case name == "owner.lock":
			if info.Size() != 0 {
				return nil, ErrCorrupt
			}
		case strings.HasPrefix(name, "torn-"):
		default:
			if _, ok := parseGeneration(name, "segment"); ok {
				continue
			}
			if g, ok := parseGeneration(name, "checkpoint"); ok {
				if g > j.generation {
					j.generation = g
				}
				continue
			}
			if g, ok := parseGeneration(name, "commit"); ok {
				if g > j.generation {
					j.generation = g
				}
				continue
			}
			return nil, fmt.Errorf("unexpected journal entry %s: %w", name, ErrCorrupt)
		}
	}
	return files, nil
}

func (j *Journal) loadCheckpoint(files map[string]int64) error {
	var generations []uint64
	for name := range files {
		if g, ok := parseGeneration(name, "commit"); ok {
			generations = append(generations, g)
		}
	}
	sort.Slice(generations, func(a, b int) bool { return generations[a] > generations[b] })
	for _, g := range generations {
		name := generationName("commit", g)
		// A short commit marker never committed. A complete corrupt marker or a
		// committed missing/corrupt snapshot must not silently resurrect ACKs.
		if files[name] < commitSize {
			continue
		}
		if files[name] != commitSize {
			return ErrCorrupt
		}
		b, err := j.readControl(name, commitSize)
		if err != nil {
			return err
		}
		if string(b[:8]) != "EVJCOM01" || binary.LittleEndian.Uint64(b[8:16]) != g || binary.LittleEndian.Uint32(b[60:]) != crc32.Checksum(b[:60], checksumTable) {
			return ErrCorrupt
		}
		checkpointName := generationName("checkpoint", g)
		size, ok := files[checkpointName]
		if !ok || size < int64(frameHeaderSize) || uint64(size) != binary.LittleEndian.Uint64(b[16:24]) {
			return ErrCorrupt
		}
		if size+commitSize > j.options.ReservedBytes/2 {
			return ErrFull
		}
		data, err := j.readControl(checkpointName, size)
		if err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(b[24:28]) != crc32.Checksum(data, checksumTable) {
			return ErrCorrupt
		}
		var c checkpoint
		if err := decodeCheckpoint(data, &c); err != nil {
			return err
		}
		if c.AgentID != j.options.AgentID {
			return ErrIdentityMismatch
		}
		if c.Generation != g {
			return ErrCorrupt
		}
		if err := validateCheckpoint(c); err != nil {
			return err
		}
		j.checkpoint = c
		for key, value := range c.Cursors {
			j.cursors[key] = value
		}
		return nil
	}
	return nil
}

func (j *Journal) readControl(name string, size int64) (b []byte, err error) {
	f, err := j.dir.open(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return io.ReadAll(io.LimitReader(f, size))
}

func decodeCheckpoint(data []byte, c *checkpoint) error {
	if len(data) < frameHeaderSize || string(data[:4]) != "EVJR" || data[4] != 1 || data[5] != 3 || data[6] != 0 || data[7] != 0 || binary.LittleEndian.Uint32(data[16:20]) != crc32.Checksum(data[:16], checksumTable) {
		return ErrCorrupt
	}
	payload := data[frameHeaderSize:]
	if uint64(len(payload)) != uint64(binary.LittleEndian.Uint32(data[8:12])) || crc32.Checksum(payload, checksumTable) != binary.LittleEndian.Uint32(data[12:16]) {
		return ErrCorrupt
	}
	if err := json.Unmarshal(payload, c); err != nil {
		return fmt.Errorf("checkpoint JSON: %w: %w", ErrCorrupt, err)
	}
	return nil
}

func validateCheckpoint(c checkpoint) error {
	if c.Version != 1 || c.Cursors == nil || c.ACKs == nil || c.States == nil || c.Health.KnownLoss == nil || c.Health.Sources == nil {
		return ErrCorrupt
	}
	previous := uint64(0)
	for _, s := range c.Segments {
		if s.Sequence <= previous || s.Sequence > c.HighSequence || s.Size < segmentHeaderSize {
			return ErrCorrupt
		}
		previous = s.Sequence
	}
	for key, value := range c.Cursors {
		if key == "" || key != value.Source {
			return ErrCorrupt
		}
	}
	for _, s := range c.States {
		switch s.State {
		case "":
			if s.FirstAttempt.IsZero() || s.Reason != "" {
				return ErrCorrupt
			}
		case "held", "quarantined":
			if !boundedText(s.Reason, 256) {
				return ErrCorrupt
			}
		default:
			return ErrCorrupt
		}
	}
	if c.Health.Retries < 0 || c.Health.Held < 0 || c.Health.Quarantined < 0 || c.Health.UnknownGaps < 0 || len(c.Health.Sources) > 256 {
		return ErrCorrupt
	}
	if len(c.Audit) > maxAudit {
		return ErrCorrupt
	}
	for _, a := range c.Audit {
		if (a.Action != "release" && a.Action != "discard") || !boundedText(a.Reason, 256) {
			return ErrCorrupt
		}
	}
	for key, value := range c.Health.KnownLoss {
		if !lossReason(key) || value < 0 {
			return ErrCorrupt
		}
	}
	for key, value := range c.Health.Sources {
		if !boundedText(key, 256) || !boundedText(value.Reason, 256) {
			return ErrCorrupt
		}
		switch value.State {
		case "healthy", "degraded", "paused", "unavailable":
		default:
			return ErrCorrupt
		}
	}
	return nil
}
