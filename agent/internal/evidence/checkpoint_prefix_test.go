package evidence

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func checkpointedQueuedEvent(t *testing.T) (Options, Envelope, string) {
	t.Helper()
	o := journalOptions(t)
	j := openJournal(t, o)
	event := appendEvidence(t, j)
	if err := j.SetSourceState(context.Background(), "syslog", "healthy", "active"); err != nil {
		t.Fatal(err)
	}
	name := j.segments[0].name
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	return o, event, filepath.Join(o.Dir, name)
}

func TestCheckpointCommittedPrefixTornFrameIsRefusedWithoutRepair(t *testing.T) {
	// Given queued evidence captured by a health checkpoint, with no ACK or
	// attempt/terminal metadata that would otherwise detect its removal.
	o, _, path := checkpointedQueuedEvent(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	header := data[segmentHeaderSize : segmentHeaderSize+frameHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12]) + 64
	if length > uint32(o.MaxEventBytes) {
		t.Fatal("fixture must remain within the frame allocation limit")
	}
	binary.LittleEndian.PutUint32(header[8:12], length)
	binary.LittleEndian.PutUint32(header[16:20], crc32.Checksum(header[:16], checksumTable))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(o.Dir)
	if err != nil {
		t.Fatal(err)
	}
	before := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(o.Dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = content
	}
	// When a CRC-valid header claims unavailable bytes inside the captured prefix,
	// fail closed before creating forensics or truncating admitted delivery state.
	opened, err := Open(o)
	if opened != nil {
		opened.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("committed-prefix torn frame accepted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatalf("committed prefix bytes changed: %v", err)
	}
	forensics, err := filepath.Glob(filepath.Join(o.Dir, "torn-*"))
	if err != nil || len(forensics) != 0 {
		t.Fatalf("committed evidence converted to forensics: %v %v", forensics, err)
	}
	entries, err = os.ReadDir(o.Dir)
	if err != nil || len(entries) != len(before) {
		t.Fatalf("journal namespace changed: %v %v", entries, err)
	}
	for name, want := range before {
		got, err := os.ReadFile(filepath.Join(o.Dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("journal file %s changed: %v", name, err)
		}
	}
}

func TestCheckpointPostCommitTornTailRemainsRecoverable(t *testing.T) {
	for _, location := range []string{"captured-segment-tail", "new-segment-tail", "new-segment-header"} {
		t.Run(location, func(t *testing.T) {
			// Given intact checkpoint-captured evidence and a later incomplete write.
			o, event, path := checkpointedQueuedEvent(t)
			prefix, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			next := journalEvent(t, o)
			next.Cursor.Offset = 999
			payload, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			frame := encodeFrame(frameEvent, payload)
			tail := frame[:frameHeaderSize+7]
			switch location {
			case "captured-segment-tail":
				if err := os.WriteFile(path, append(append([]byte(nil), prefix...), tail...), 0600); err != nil {
					t.Fatal(err)
				}
			case "new-segment-tail":
				if err := os.WriteFile(filepath.Join(o.Dir, segmentName(2)), append(segmentHeader(o.AgentID, 2), tail...), 0600); err != nil {
					t.Fatal(err)
				}
			case "new-segment-header":
				tail = segmentHeader(o.AgentID, 2)[:17]
				if err := os.WriteFile(filepath.Join(o.Dir, segmentName(2)), tail, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// When reopened, only the post-checkpoint suffix is repaired/preserved.
			j := openJournal(t, o)
			got, ok, err := j.Peek(context.Background())
			if err != nil || !ok || got.EventID != event.EventID {
				t.Fatalf("captured evidence lost: %v %v", ok, err)
			}
			if cursor, ok := j.Cursor("syslog"); !ok || cursor.Offset != 42 {
				t.Fatalf("incomplete cursor advanced: %#v %v", cursor, ok)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, prefix) {
				t.Fatalf("captured prefix changed: %v", err)
			}
			forensics, err := filepath.Glob(filepath.Join(o.Dir, "torn-*"))
			if err != nil || len(forensics) != 1 {
				t.Fatalf("incomplete suffix absent: %v %v", forensics, err)
			}
			preserved, err := os.ReadFile(forensics[0])
			if err != nil || !bytes.Equal(preserved, tail) {
				t.Fatalf("suffix changed: %v", err)
			}
			appendEvidence(t, j)
		})
	}
}
