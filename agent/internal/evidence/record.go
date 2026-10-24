package evidence

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	segmentHeaderSize      = 64
	frameHeaderSize        = 20
	frameEvent        byte = 1
	frameBaseline     byte = 2
)

var checksumTable = crc32.MakeTable(crc32.Castagnoli)

func segmentHeader(agentID string, sequence uint64) []byte {
	b := make([]byte, segmentHeaderSize)
	copy(b, "EVJSEG01")
	copy(b[8:44], agentID)
	binary.LittleEndian.PutUint64(b[44:52], sequence)
	binary.LittleEndian.PutUint32(b[60:], crc32.Checksum(b[:60], checksumTable))
	return b
}

func checkSegmentHeader(b []byte, agentID string, sequence uint64) error {
	if !bytes.Equal(b[:8], []byte("EVJSEG01")) || binary.LittleEndian.Uint32(b[60:]) != crc32.Checksum(b[:60], checksumTable) || binary.LittleEndian.Uint64(b[44:52]) != sequence {
		return fmt.Errorf("segment header: %w", ErrCorrupt)
	}
	if string(b[8:44]) != agentID {
		return ErrIdentityMismatch
	}
	return nil
}

func encodeFrame(kind byte, payload []byte) []byte {
	b := make([]byte, frameHeaderSize+len(payload))
	copy(b, "EVJR")
	b[4], b[5] = 1, kind
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(b[12:16], crc32.Checksum(payload, checksumTable))
	binary.LittleEndian.PutUint32(b[16:20], crc32.Checksum(b[:16], checksumTable))
	copy(b[frameHeaderSize:], payload)
	return b
}

type record struct {
	kind   byte
	event  Envelope
	cursor Cursor
	next   int64
}

// readRecord allocates only after the checksummed length is bounded. EOF means
// a physically incomplete frame; malformed complete frames are never repaired.
func readRecord(r io.ReaderAt, offset int64, maxBytes int) (record, error) {
	var h [frameHeaderSize]byte
	if _, err := r.ReadAt(h[:], offset); err != nil {
		return record{}, err
	}
	if string(h[:4]) != "EVJR" || h[4] != 1 || h[6] != 0 || h[7] != 0 || binary.LittleEndian.Uint32(h[16:]) != crc32.Checksum(h[:16], checksumTable) {
		return record{}, fmt.Errorf("frame header at %d: %w", offset, ErrCorrupt)
	}
	n := uint64(binary.LittleEndian.Uint32(h[8:12]))
	if n == 0 || n > uint64(maxBytes) {
		return record{}, fmt.Errorf("frame length %d: %w", n, ErrCorrupt)
	}
	b := make([]byte, int(n))
	if _, err := r.ReadAt(b, offset+frameHeaderSize); err != nil {
		return record{}, err
	}
	if binary.LittleEndian.Uint32(h[12:16]) != crc32.Checksum(b, checksumTable) {
		return record{}, fmt.Errorf("frame checksum at %d: %w", offset, ErrCorrupt)
	}
	v := record{kind: h[5], next: offset + frameHeaderSize + int64(n)}
	switch v.kind {
	case frameEvent:
		if err := json.Unmarshal(b, &v.event); err != nil {
			return record{}, fmt.Errorf("event JSON: %w: %w", ErrCorrupt, err)
		}
		if err := ValidateAgentID(v.event.EventID); err != nil {
			return record{}, fmt.Errorf("event identity: %w: %w", ErrCorrupt, err)
		}
		if v.event.ProtocolVersion != 2 {
			return record{}, fmt.Errorf("event protocol: %w", ErrCorrupt)
		}
		if v.event.Cursor != nil && v.event.Cursor.Source == "" {
			return record{}, fmt.Errorf("event cursor source: %w", ErrCorrupt)
		}
	case frameBaseline:
		if err := json.Unmarshal(b, &v.cursor); err != nil {
			return record{}, fmt.Errorf("cursor JSON: %w: %w", ErrCorrupt, err)
		}
		if v.cursor.Source == "" {
			return record{}, fmt.Errorf("baseline source: %w", ErrCorrupt)
		}
	default:
		return record{}, fmt.Errorf("frame kind %d: %w", v.kind, ErrCorrupt)
	}
	return v, nil
}
