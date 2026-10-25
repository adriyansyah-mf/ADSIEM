package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func journalOptions(t *testing.T) Options {
	t.Helper()
	return Options{Dir: filepath.Join(t.TempDir(), "journal"), AgentID: "11111111-1111-4111-8111-111111111111", MaxBytes: 1 << 20, SegmentBytes: 64 << 10, ReservedBytes: 16 << 10, MaxEventBytes: 4096}
}

func journalEvent(t *testing.T, o Options) Envelope {
	t.Helper()
	e, err := NewEnvelope(o.AgentID, "host", Draft{LogType: "syslog", RawMessage: "number=1", Cursor: &Cursor{Source: "syslog", Identity: "inode", Generation: "one", Offset: 42}}, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func openJournal(t *testing.T, o Options) *Journal {
	t.Helper()
	j, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Error(err)
		}
	})
	return j
}

func TestAppendSurvivesReopen(t *testing.T) {
	// Given a durable admission.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// When reopening, immutable identity, time and cursor survive exactly.
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(got, e) {
		t.Fatalf("recovery: %#v %v %v", got, ok, err)
	}
}

type syncFault struct{ storage }

func (s syncFault) Sync() error { return os.ErrPermission }

func TestSyncFailureDoesNotCommitCursor(t *testing.T) {
	// Given an actual file with only its flush operation failing.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	j.writer = syncFault{j.writer}
	// When the flush fails, neither the cursor nor later admission is committed.
	if err := j.Append(context.Background(), e); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("append: %v", err)
	}
	if c, ok := j.Cursor("syslog"); ok {
		t.Fatalf("committed: %#v", c)
	}
	if err := j.Append(context.Background(), e); err == nil {
		t.Fatal("poisoned writer accepted another event")
	}
}

func TestSecondWriterRefused(t *testing.T) {
	// Given a live owner.
	o := journalOptions(t)
	openJournal(t, o)
	// When another owner opens the same journal.
	second, err := Open(o)
	if second != nil {
		second.Close()
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("lock: %v", err)
	}
}

func firstSegment(t *testing.T, o Options) string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(o.Dir, "segment-*.evj"))
	if err != nil || len(names) == 0 {
		t.Fatalf("segments: %v %v", names, err)
	}
	return names[0]
}

func TestTornTailPreservesPrefix(t *testing.T) {
	// Given a complete first record and a partial final record.
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	path := firstSegment(t, o)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, int64(len(before)-7)); err != nil {
		t.Fatal(err)
	}
	// When recovering, retain the prefix and a forensic suffix.
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != e.EventID {
		t.Fatalf("prefix: %v %v", ok, err)
	}
	files, err := filepath.Glob(filepath.Join(o.Dir, "torn-*"))
	if err != nil || len(files) != 1 {
		t.Fatalf("forensic suffix: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil || len(data) == 0 {
		t.Fatalf("forensic bytes: %v", err)
	}
}

func TestInteriorCorruptionBlocks(t *testing.T) {
	// Given a corrupt payload followed by another complete event.
	o := journalOptions(t)
	j := openJournal(t, o)
	for range 2 {
		if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	path := firstSegment(t, o)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[segmentHeaderSize+frameHeaderSize+10] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	// When reopening, refuse corruption without modifying any evidence.
	broken, err := Open(o)
	if broken != nil {
		broken.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corruption: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(after, data) {
		t.Fatalf("evidence changed: %v", err)
	}
}
