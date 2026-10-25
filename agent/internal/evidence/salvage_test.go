package evidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// salvageFixture is a closed journal with 12 file events (the first 4
// delivered, #6 held, #7 attempted), a configured-path marker, and the frame
// of event #9 damaged on disk so that Open refuses the journal.
type salvageFixture struct {
	o        Options
	events   []Envelope
	damaged  string // event ID whose frame is broken
	cursors  map[string]Cursor
	attempts map[string]time.Time
}

func newSalvageFixture(t *testing.T) salvageFixture {
	t.Helper()
	ctx := context.Background()
	o := journalOptions(t)
	j := openJournal(t, o)
	marker := Cursor{Source: "marker:/var/log/app.log", Generation: "g0", Identity: "configured", Empty: true}
	if err := j.SaveBaseline(ctx, marker); err != nil {
		t.Fatal(err)
	}
	f := salvageFixture{o: o, attempts: map[string]time.Time{}}
	base := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	for n := range 12 {
		e, err := NewEnvelope(o.AgentID, "host", Draft{LogType: "syslog", Location: "/var/log/app.log",
			RawMessage: fmt.Sprintf("line %d", n),
			Cursor:     &Cursor{Source: "file:/var/log/app.log", Generation: "g1", Identity: "1:2", Offset: int64(10 * (n + 1))}},
			base.Add(time.Duration(n)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		f.events = append(f.events, e)
	}
	for _, e := range f.events[:4] {
		if err := j.Ack(ctx, e.EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Hold(ctx, f.events[6].EventID, "receipt_uncertainty_window"); err != nil {
		t.Fatal(err)
	}
	f.attempts[f.events[7].EventID] = base.Add(time.Hour)
	if err := j.MarkAttempt(ctx, f.events[7].EventID, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.cursors = j.Cursors()
	f.damaged = f.events[9].EventID
	p := j.positions(f.damaged)[0]
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// Overwrite bytes inside the frame's payload: both checksums still in place.
	seg, err := os.OpenFile(filepath.Join(o.Dir, segmentName(p.Sequence)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seg.WriteAt([]byte("CORRUPT"), p.Offset+frameHeaderSize+10); err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(o); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("damaged journal opened: %v", err)
	}
	return f
}

// fingerprint hashes every file of dir, so a test can prove nothing changed.
func fingerprint(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	sums := map[string][32]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "owner.lock" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sums[e.Name()] = sha256.Sum256(b)
	}
	return sums
}

func pending(t *testing.T, j *Journal) []string {
	t.Helper()
	var ids []string
	for {
		batch, err := j.PeekBatch(context.Background(), 100, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch) == 0 {
			return ids
		}
		var receipts []Receipt
		for _, e := range batch {
			ids = append(ids, e.EventID)
			receipts = append(receipts, Receipt{EventID: e.EventID, ReceiptID: testReceipt})
		}
		// acknowledge in the test only, to walk the whole queue
		if err := j.AckBatch(context.Background(), receipts); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSalvageImportsReadableUndeliveredEvidenceAndKeepsTheOriginal(t *testing.T) {
	f := newSalvageFixture(t)
	before := fingerprint(t, f.o.Dir)
	target := filepath.Join(filepath.Dir(f.o.Dir), "journal.salvage")

	report, err := Salvage(context.Background(), f.o, target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fingerprint(t, f.o.Dir); !reflect.DeepEqual(got, before) {
		t.Fatal("salvage changed the damaged journal")
	}
	if !report.CheckpointUsable || report.UnreadableRegions != 1 || report.Delivered != 4 || report.Imported != 7 {
		t.Fatalf("report %+v", report)
	}

	o := f.o
	o.Dir = target
	j := openJournal(t, o)
	for source, c := range f.cursors { // files resume where they were, the marker survives
		if got, ok := j.Cursor(source); !ok || !reflect.DeepEqual(got, c) {
			t.Fatalf("cursor %s: got %+v want %+v", source, got, c)
		}
	}
	if at, ok, err := j.FirstAttempt(context.Background(), f.events[7].EventID); err != nil || !ok || !at.Equal(f.attempts[f.events[7].EventID]) {
		t.Fatalf("first attempt not kept: %v %v %v", at, ok, err)
	}
	h := j.Snapshot()
	if h.Held != 1 || h.UnknownGaps != 1 {
		t.Fatalf("health %+v", h)
	}
	var want []string
	for i, e := range f.events {
		if i >= 4 && i != 6 && i != 9 { // undelivered, not held, not destroyed
			want = append(want, e.EventID)
		}
	}
	got := pending(t, j)
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deliverable after salvage %v, want %v", got, want)
	}
}

func TestSalvageKeepsEventIdentityAndContent(t *testing.T) {
	f := newSalvageFixture(t)
	target := filepath.Join(filepath.Dir(f.o.Dir), "journal.salvage")
	if _, err := Salvage(context.Background(), f.o, target); err != nil {
		t.Fatal(err)
	}
	o := f.o
	o.Dir = target
	j := openJournal(t, o)
	for _, e := range f.events[4:] {
		if e.EventID == f.damaged {
			continue
		}
		events, _, err := j.occurrences(context.Background(), e.EventID)
		if err != nil || len(events) != 1 || !reflect.DeepEqual(events[0], e) {
			t.Fatalf("event %s changed: %+v %v", e.EventID, events, err)
		}
	}
}

func TestSalvageWithoutACheckpointImportsEverythingReadable(t *testing.T) {
	f := newSalvageFixture(t)
	entries, _ := os.ReadDir(f.o.Dir)
	for _, e := range entries {
		if _, ok := parseGeneration(e.Name(), "checkpoint"); ok {
			if err := os.WriteFile(filepath.Join(f.o.Dir, e.Name()), []byte("garbage"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	target := filepath.Join(filepath.Dir(f.o.Dir), "journal.salvage")
	report, err := Salvage(context.Background(), f.o, target)
	if err != nil {
		t.Fatal(err)
	}
	// Delivered events are sent again: the server answers them as duplicates.
	if report.CheckpointUsable || report.Imported != 11 || report.Delivered != 0 {
		t.Fatalf("report %+v", report)
	}
}

func TestSalvageRefusesANonEmptyTarget(t *testing.T) {
	f := newSalvageFixture(t)
	target := filepath.Join(filepath.Dir(f.o.Dir), "journal.salvage")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Salvage(context.Background(), f.o, target); err == nil {
		t.Fatal("salvaged into a directory that already holds files")
	}
}
