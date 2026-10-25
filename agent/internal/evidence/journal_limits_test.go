package evidence

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestOpenRequiresAgentIdentity(t *testing.T) {
	o := journalOptions(t)
	o.AgentID = ""
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrInvalidAgentID) {
		t.Fatalf("identity: %v", err)
	}
}

func TestJournalIdentityMismatch(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	o.AgentID = "22222222-2222-4222-8222-222222222222"
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("binding: %v", err)
	}
}

func TestAppendProtectsCursorSnapshots(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	if err := j.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e.Cursor.Offset = 500
	got, _, err := j.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.Cursor.Offset = 600
	c, ok := j.Cursor("syslog")
	if !ok || c.Offset != 42 {
		t.Fatalf("snapshot: %#v %v", c, ok)
	}
}

func TestBaselineSurvivesReopen(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	c := Cursor{Source: "file", Identity: "inode", Offset: 123, Empty: true}
	if err := j.SaveBaseline(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = openJournal(t, o)
	got, ok := j.Cursor("file")
	if !ok || got != c {
		t.Fatalf("baseline: %#v %v", got, ok)
	}
	if _, ok, err := j.Peek(context.Background()); err != nil || ok {
		t.Fatalf("baseline became event: %v %v", ok, err)
	}
}

type shortFault struct{ storage }

func (s shortFault) Write(p []byte) (int, error) { return s.storage.Write(p[:len(p)/2]) }

func TestShortWritePoisonsWriter(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	j.writer = shortFault{j.writer}
	if err := j.Append(context.Background(), journalEvent(t, o)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if _, ok := j.Cursor("syslog"); ok {
		t.Fatal("short write committed cursor")
	}
	if err := j.Append(context.Background(), journalEvent(t, o)); err == nil {
		t.Fatal("poisoned writer accepted event")
	}
}

func TestAdmissionRespectsDiskBudget(t *testing.T) {
	o := journalOptions(t)
	o.MaxBytes, o.SegmentBytes, o.ReservedBytes = 8192, 4096, 2048
	o.MaxEventBytes = 2048
	j := openJournal(t, o)
	e := journalEvent(t, o)
	e.RawMessage = strings.Repeat("x", 900)
	for i := 0; i < 20; i++ {
		err := j.Append(context.Background(), e)
		if errors.Is(err, ErrFull) {
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			j = openJournal(t, o)
			got, ok, err := j.Peek(context.Background())
			if err != nil || !ok || got.EventID != e.EventID {
				t.Fatalf("full queue lost evidence: %v %v", ok, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("budget never applied")
}

func TestOversizeDoesNotPoisonWriter(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	e := journalEvent(t, o)
	e.RawMessage = strings.Repeat("x", o.MaxEventBytes)
	if err := j.Append(context.Background(), e); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize: %v", err)
	}
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledAppendDoesNotCommit(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := j.Append(ctx, journalEvent(t, o)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, ok := j.Cursor("syslog"); ok {
		t.Fatal("canceled append committed")
	}
}
