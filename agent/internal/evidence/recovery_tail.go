package evidence

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// A rotation interrupted before the first frame cannot strand earlier durable
// events. Only an exact prefix of the expected final header is repairable.
func (j *Journal) repairHeader(f *os.File, s segment) error {
	header := segmentHeader(j.options.AgentID, s.sequence)
	var prefix [segmentHeaderSize]byte
	if _, err := f.ReadAt(prefix[:s.size], 0); err != nil {
		return err
	}
	if !bytes.Equal(prefix[:s.size], header[:s.size]) {
		return fmt.Errorf("incomplete header mismatch: %w", ErrCorrupt)
	}
	// The copy retains the old bytes, so the repaired header is wholly additional.
	if segmentHeaderSize > j.options.MaxBytes-j.used {
		return ErrFull
	}
	if err := j.preserveTail(f, s, 0); err != nil {
		return err
	}
	j.used -= s.size
	if err := writeFull(f, header); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush repaired header: %w", err)
	}
	if err := j.dir.sync(); err != nil {
		return fmt.Errorf("persist repaired header name: %w", err)
	}
	j.used += segmentHeaderSize
	return nil
}

// preserveTail saves and flushes the exact incomplete suffix before truncation.
// A valid frame after the break proves interior damage, so refuse recovery.
func (j *Journal) preserveTail(f *os.File, s segment, offset int64) (err error) {
	for probe := offset + 1; probe+frameHeaderSize <= s.size; probe++ {
		var magic [4]byte
		if _, err := f.ReadAt(magic[:], probe); err != nil {
			return err
		}
		if string(magic[:]) == "EVJR" {
			if _, err := readRecord(f, probe, j.options.MaxEventBytes); err == nil {
				return fmt.Errorf("complete frame after damaged frame: %w", ErrCorrupt)
			}
		}
	}
	tailBytes := s.size - offset
	if tailBytes > int64(frameHeaderSize)+int64(j.options.MaxEventBytes) {
		return ErrCorrupt
	}
	if tailBytes > j.options.MaxBytes-j.used {
		return fmt.Errorf("forensic recovery requires reserve: %w", ErrFull)
	}
	var copyFile *os.File
	for n := uint64(0); ; n++ {
		name := fmt.Sprintf("torn-%020d-%020d-%020d", s.sequence, offset, n)
		copyFile, err = j.dir.open(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("create forensic suffix: %w", err)
	}
	defer func() { err = errors.Join(err, copyFile.Close()) }()
	buffer := make([]byte, 32<<10)
	if _, err := io.CopyBuffer(copyFile, io.NewSectionReader(f, offset, tailBytes), buffer); err != nil {
		return fmt.Errorf("copy forensic suffix: %w", err)
	}
	if err := copyFile.Sync(); err != nil {
		return fmt.Errorf("flush forensic suffix: %w", err)
	}
	if err := j.dir.sync(); err != nil {
		return fmt.Errorf("persist forensic name: %w", err)
	}
	j.used += tailBytes
	if err := f.Truncate(offset); err != nil {
		return fmt.Errorf("truncate incomplete suffix: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flush recovery truncation: %w", err)
	}
	return nil
}
