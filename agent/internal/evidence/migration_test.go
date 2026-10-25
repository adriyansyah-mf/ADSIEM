package evidence

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const migrationAgent = "11111111-1111-4111-8111-111111111111"

// spillLines are three entries in the legacy codec: "logType\x00location\x00raw",
// a newline inside a message stored as \x1e.
var spillLines = []string{
	"linux_auth\x00/var/log/auth.log\x00sshd: Failed password for root from 203.0.113.9",
	"syslog\x00\x00multi\x1eline message",
	"linux_process_exec\x00\x00Image=/usr/bin/curl",
}

// newMigrationFixture opens a real journal and writes a legacy spill.
func newMigrationFixture(t *testing.T) (*Journal, string) {
	t.Helper()
	j := openJournal(t, journalOptions(t))
	path := filepath.Join(t.TempDir(), "spill.log")
	if err := os.WriteFile(path, []byte(strings.Join(spillLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return j, path
}

// drainEvents returns every unacknowledged event, acknowledging none.
func drainEvents(t *testing.T, j *Journal) []Envelope {
	t.Helper()
	var out []Envelope
	err := j.walkEvents(context.Background(), func(e Envelope, p eventPosition) (bool, error) {
		if !acknowledged(j.checkpoint, p) {
			out = append(out, e)
		}
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestImportPreservesOriginal(t *testing.T) {
	j, path := newMigrationFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("import destroyed original spill")
	}
}

func TestImportDecodesLegacyEntriesAsLabelledEvidence(t *testing.T) {
	j, path := newMigrationFixture(t)
	if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil {
		t.Fatal(err)
	}
	got := drainEvents(t, j)
	if len(got) != 3 {
		t.Fatalf("imported %d events", len(got))
	}
	if got[0].LogType != "linux_auth" || got[0].Location != "/var/log/auth.log" || !strings.HasPrefix(got[0].RawMessage, "sshd:") {
		t.Fatalf("first %+v", got[0])
	}
	if got[1].RawMessage != "multi\nline message" {
		t.Fatalf("legacy newline marker not decoded: %q", got[1].RawMessage)
	}
	for _, e := range got {
		if !e.LegacyImport || e.ProtocolVersion != 2 || e.Hostname != "host" || e.Cursor == nil || !strings.HasPrefix(e.Cursor.Source, legacySourcePrefix) {
			t.Fatalf("not a labelled legacy import: %+v", e)
		}
		if err := ValidateAgentID(e.EventID); err != nil {
			t.Fatalf("event id %q: %v", e.EventID, err)
		}
	}
}

func TestImportIsDoneOnceAndResumesAfterEveryInterruption(t *testing.T) {
	for stopAfter := 1; stopAfter <= len(spillLines); stopAfter++ {
		j, path := newMigrationFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		imported := 0
		afterImportRecord = func() {
			if imported++; imported == stopAfter {
				cancel() // the agent is stopped right after this record's flush
			}
		}
		err := ImportLegacy(ctx, j, path, migrationAgent, "host")
		afterImportRecord = nil
		if stopAfter < len(spillLines) && !errors.Is(err, context.Canceled) {
			t.Fatalf("stop after %d: %v", stopAfter, err)
		}
		first := drainEvents(t, j)
		if len(first) != stopAfter {
			t.Fatalf("stop after %d: %d committed", stopAfter, len(first))
		}
		// restart: resumes at the committed offset with the same identities
		if err := j.Close(); err != nil {
			t.Fatal(err)
		}
		j = openJournal(t, j.options)
		if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil {
			t.Fatal(err)
		}
		if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil { // completed: no-op
			t.Fatal(err)
		}
		all := drainEvents(t, j)
		if len(all) != len(spillLines) {
			t.Fatalf("stop after %d: %d events after resume (duplicated or lost)", stopAfter, len(all))
		}
		for i, e := range first {
			if all[i].EventID != e.EventID {
				t.Fatalf("identity changed across resume")
			}
		}
		if !ImportComplete(j, path) {
			t.Fatal("completion marker missing")
		}
	}
}

func TestImportIdentitiesAreDeterministic(t *testing.T) {
	j1, path := newMigrationFixture(t)
	j2 := openJournal(t, journalOptions(t))
	for _, j := range []*Journal{j1, j2} {
		if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil {
			t.Fatal(err)
		}
	}
	a, b := drainEvents(t, j1), drainEvents(t, j2)
	for i := range a {
		if a[i].EventID != b[i].EventID {
			t.Fatal("the same spill line got different identities")
		}
	}
}

func TestImportMissingOrEmptySpillIsANoOp(t *testing.T) {
	j := openJournal(t, journalOptions(t))
	dir := t.TempDir()
	if err := ImportLegacy(context.Background(), j, filepath.Join(dir, "absent.log"), migrationAgent, "host"); err != nil {
		t.Fatalf("missing spill: %v", err)
	}
	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportLegacy(context.Background(), j, empty, migrationAgent, "host"); err != nil {
		t.Fatalf("empty spill: %v", err)
	}
	if len(drainEvents(t, j)) != 0 {
		t.Fatal("events from nothing")
	}
}

func TestImportOfAGrownOrReplacedSpill(t *testing.T) {
	j, path := newMigrationFixture(t)
	ctx := context.Background()
	if err := ImportLegacy(ctx, j, path, migrationAgent, "host"); err != nil {
		t.Fatal(err)
	}
	// an old agent appended after the import: only the new line is imported
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("syslog\x00\x00appended later\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if ImportComplete(j, path) {
		t.Fatal("grown spill still reported complete")
	}
	if err := ImportLegacy(ctx, j, path, migrationAgent, "host"); err != nil {
		t.Fatal(err)
	}
	if got := drainEvents(t, j); len(got) != 4 || got[3].RawMessage != "appended later" {
		t.Fatalf("after growth: %d events", len(got))
	}
	// a different file substituted at the path: a new import from its start
	if err := os.WriteFile(path, []byte("syslog\x00\x00replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportLegacy(ctx, j, path, migrationAgent, "host"); err != nil {
		t.Fatal(err)
	}
	got := drainEvents(t, j)
	if len(got) != 5 || got[4].RawMessage != "replacement" || got[4].Cursor.Generation == got[0].Cursor.Generation {
		t.Fatalf("replacement: %d events", len(got))
	}
}

func TestImportOversizedLineIsReportedNotSkippedSilently(t *testing.T) {
	j := openJournal(t, journalOptions(t))
	path := filepath.Join(t.TempDir(), "spill.log")
	big := "syslog\x00\x00" + strings.Repeat("x", 2*j.options.MaxEventBytes)
	if err := os.WriteFile(path, []byte(spillLines[0]+"\n"+big+"\n"+spillLines[2]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil {
		t.Fatal(err)
	}
	if got := drainEvents(t, j); len(got) != 2 {
		t.Fatalf("imported %d", len(got))
	}
	h := j.Snapshot()
	if h.KnownLoss["legacy_import"] != 1 {
		t.Fatalf("oversized legacy entry not counted: %+v", h.KnownLoss)
	}
	if err := ImportLegacy(context.Background(), j, path, migrationAgent, "host"); err != nil || j.Snapshot().KnownLoss["legacy_import"] != 1 {
		t.Fatalf("rerun recounted: %v", err)
	}
}

func TestImportBlockedByCapacityKeepsProgressAndHealth(t *testing.T) {
	o := journalOptions(t)
	o.MaxBytes, o.SegmentBytes, o.ReservedBytes, o.MaxEventBytes = 64<<10, 32<<10, 16<<10, 4096
	j := openJournal(t, o)
	path := filepath.Join(t.TempDir(), "spill.log")
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "syslog\x00\x00"+strings.Repeat("y", 300))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ImportLegacy(context.Background(), j, path, migrationAgent, "host")
	if !errors.Is(err, ErrMigrationBlocked) {
		t.Fatalf("over budget: %v", err)
	}
	partial := drainEvents(t, j)
	if len(partial) == 0 || len(partial) == len(lines) {
		t.Fatalf("partial import %d", len(partial))
	}
	if s := j.Snapshot().Sources[legacyHealthSource]; s.State != "paused" || s.Reason != "migration_blocked" {
		t.Fatalf("health %+v", s)
	}
	// delivery frees space; the import resumes where it stopped
	for _, e := range partial {
		if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; ; attempt++ {
		err := ImportLegacy(context.Background(), j, path, migrationAgent, "host")
		if err == nil {
			break
		}
		if !errors.Is(err, ErrMigrationBlocked) || attempt > 50 {
			t.Fatal(err)
		}
		for _, e := range drainEvents(t, j) {
			if err := j.Ack(context.Background(), e.EventID, testReceipt); err != nil {
				t.Fatal(err)
			}
		}
		if err := j.Compact(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !ImportComplete(j, path) {
		t.Fatal("not complete after space was freed")
	}
	if s := j.Snapshot().Sources[legacyHealthSource]; s.State != "healthy" {
		t.Fatalf("health after completion %+v", s)
	}
}
