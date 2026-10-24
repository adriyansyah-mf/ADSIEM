package evidence

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIncompleteFrameCannotHideFollowingEvidence(t *testing.T) {
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
	h := data[segmentHeaderSize : segmentHeaderSize+frameHeaderSize]
	// An internally consistent damaged length must not swallow later frames.
	binary.LittleEndian.PutUint32(h[8:12], uint32(o.MaxEventBytes))
	binary.LittleEndian.PutUint32(h[16:20], crc32.Checksum(h[:16], checksumTable))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	j, err = Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("interior damage: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(after, data) {
		t.Fatalf("changed evidence: %v", err)
	}
}

func TestCompleteFinalCorruptionIsRefused(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	path := firstSegment(t, o)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	j, err = Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("complete corrupt tail: %v", err)
	}
}

func TestTornHeaderPreservesExactSuffix(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	path := firstSegment(t, o)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	suffix := []byte("EVJR\x01")
	if _, err := f.Write(suffix); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	openJournal(t, o)
	files, err := filepath.Glob(filepath.Join(o.Dir, "torn-*"))
	if err != nil || len(files) != 1 {
		t.Fatalf("copies: %v %v", files, err)
	}
	got, err := os.ReadFile(files[0])
	if err != nil || !reflect.DeepEqual(got, suffix) {
		t.Fatalf("suffix %q: %v", got, err)
	}
}

func TestSyncFailureRecoveryMayReplayCompleteFrame(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	j.writer = syncFault{j.writer}
	if err := j.Append(context.Background(), e); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if _, ok, err := j.Peek(context.Background()); ok || err != nil {
		t.Fatalf("uncommitted peek: %v %v", ok, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	got, ok, err := j.Peek(context.Background())
	if err != nil || !ok || got.EventID != e.EventID {
		t.Fatalf("complete uncertain frame: %v %v", ok, err)
	}
}

func TestBaselineSyncFailureDoesNotCommit(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	j.writer = syncFault{j.writer}
	if err := j.SaveBaseline(context.Background(), Cursor{Source: "empty", Empty: true}); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if _, ok := j.Cursor("empty"); ok {
		t.Fatal("failed baseline committed")
	}
}

func TestOpenRejectsSegmentSmallerThanFraming(t *testing.T) {
	o := journalOptions(t)
	o.SegmentBytes, o.MaxEventBytes = 32, 16
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("framing budget: %v", err)
	}
}
