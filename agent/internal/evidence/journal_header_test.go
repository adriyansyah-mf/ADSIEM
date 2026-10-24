package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRotationHeaderCrashPreservesAdmittedPrefix(t *testing.T) {
	for _, cut := range []int{0, 5, 40, 63} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			o := journalOptions(t)
			j := openJournal(t, o)
			e := journalEvent(t, o)
			if err := j.Append(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			header := segmentHeader(o.AgentID, 2)
			path := filepath.Join(o.Dir, "segment-00000000000000000002.evj")
			if err := os.WriteFile(path, header[:cut], 0600); err != nil {
				t.Fatal(err)
			}
			j = openJournal(t, o)
			got, ok, err := j.Peek(context.Background())
			if err != nil || !ok || got.EventID != e.EventID {
				t.Fatalf("admitted prefix stranded: %v %v", ok, err)
			}
			files, err := filepath.Glob(filepath.Join(o.Dir, "torn-*"))
			if err != nil || len(files) != 1 {
				t.Fatalf("forensic header: %v %v", files, err)
			}
			data, err := os.ReadFile(files[0])
			if err != nil || !reflect.DeepEqual(data, header[:cut]) {
				t.Fatalf("forensic prefix: %x %v", data, err)
			}
			if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
				t.Fatalf("repaired writer: %v", err)
			}
		})
	}
}

func TestCorruptShortHeaderIsRefused(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	data := []byte("broken")
	path := firstSegment(t, o)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatching short header: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(after, data) {
		t.Fatalf("corrupt bytes changed: %v", err)
	}
}

func TestQuotaShrinkRefusesWithoutDroppingBacklog(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
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
	o.MaxBytes, o.SegmentBytes, o.ReservedBytes, o.MaxEventBytes = 128, 96, 32, 64
	j, err = Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrFull) {
		t.Fatalf("quota shrink: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("quota shrink dropped evidence: %v", err)
	}
}

func TestInteriorShortHeaderIsRefused(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	path := firstSegment(t, o)
	prefix := segmentHeader(o.AgentID, 1)[:5]
	if err := os.WriteFile(path, prefix, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Dir, "segment-00000000000000000002.evj"), segmentHeader(o.AgentID, 2), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("interior short header: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(after, prefix) {
		t.Fatalf("interior bytes changed: %v", err)
	}
}

func TestHeaderRepairRefusesWithoutForensicCapacity(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
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
	tailPath := filepath.Join(o.Dir, "segment-00000000000000000002.evj")
	tail := segmentHeader(o.AgentID, 2)[:63]
	if err := os.WriteFile(tailPath, tail, 0600); err != nil {
		t.Fatal(err)
	}
	o.MaxBytes = int64(len(before) + len(tail) + 32)
	o.SegmentBytes, o.MaxEventBytes, o.ReservedBytes = int64(len(before)), len(before), 0
	j, err = Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrFull) {
		t.Fatalf("repair reserve: %v", err)
	}
	for name, want := range map[string][]byte{path: before, tailPath: tail} {
		after, err := os.ReadFile(name)
		if err != nil || !reflect.DeepEqual(after, want) {
			t.Fatalf("repair changed %s: %v", name, err)
		}
	}
}
