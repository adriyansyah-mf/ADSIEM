package tailer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/evidence"
)

const testAgentID = "11111111-1111-4111-8111-111111111111"

type tailEnv struct {
	t         *testing.T
	opts      evidence.Options
	journal   *evidence.Journal
	publisher *evidence.Publisher
}

func newTailEnv(t *testing.T) *tailEnv {
	t.Helper()
	env := &tailEnv{t: t, opts: evidence.Options{Dir: filepath.Join(t.TempDir(), "journal"), AgentID: testAgentID,
		MaxBytes: 1 << 20, SegmentBytes: 64 << 10, ReservedBytes: 16 << 10, MaxEventBytes: 4096}}
	env.open()
	t.Cleanup(env.close)
	return env
}

func (e *tailEnv) open() {
	e.t.Helper()
	j, err := evidence.Open(e.opts)
	if err != nil {
		e.t.Fatal(err)
	}
	e.journal, e.publisher = j, evidence.NewPublisher(j, testAgentID, "host", nil)
}

func (e *tailEnv) close() {
	if e.journal == nil {
		return
	}
	if err := e.publisher.Stop(context.Background()); err != nil {
		e.t.Error(err)
	}
	if err := e.journal.Close(); err != nil {
		e.t.Error(err)
	}
	e.journal = nil
}

// restart simulates an agent restart: the journal is closed and reopened.
func (e *tailEnv) restart() {
	e.close()
	e.open()
}

// capture records every successful admission; fail decides an error to
// return instead of admitting (disk pressure, storage failure).
type capture struct {
	mu     sync.Mutex
	sink   DurableSink
	drafts []evidence.Draft
	tries  []evidence.Draft
	fail   func(try int, d evidence.Draft) error
}

func (c *capture) Submit(ctx context.Context, d evidence.Draft) (evidence.Envelope, error) {
	c.mu.Lock()
	c.tries = append(c.tries, d)
	try := len(c.tries)
	fail := c.fail
	c.mu.Unlock()
	if fail != nil {
		if err := fail(try, d); err != nil {
			return evidence.Envelope{}, err
		}
	}
	e, err := c.sink.Submit(ctx, d)
	if err == nil {
		c.mu.Lock()
		c.drafts = append(c.drafts, d)
		c.mu.Unlock()
	}
	return e, err
}

func (c *capture) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.drafts))
	for i, d := range c.drafts {
		out[i] = d.RawMessage
	}
	return out
}

func (c *capture) snapshot() []evidence.Draft {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]evidence.Draft(nil), c.drafts...)
}

type running struct {
	cancel context.CancelFunc
	done   chan error
	cap    *capture
}

// tail starts the real TailDurable against a capturing sink over the publisher.
func (e *tailEnv) tail(path, logType string, fail func(int, evidence.Draft) error) *running {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1), cap: &capture{sink: e.publisher, fail: fail}}
	go func() { r.done <- TailDurable(ctx, path, logType, e.journal, r.cap) }()
	return r
}

// stop cancels and joins the collector goroutine.
func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("TailDurable: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TailDurable did not stop")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *tailEnv) baselined(t *testing.T, path string) {
	t.Helper()
	waitFor(t, "baseline of "+path, func() bool {
		_, ok := e.journal.Cursor(fileSourcePrefix + path)
		return ok
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// runDurableTailFixture: empty source, persisted baseline, append raw, run the
// real collector until count admissions, then join it.
func runDurableTailFixture(t *testing.T, raw string, count int) []evidence.Draft {
	t.Helper()
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, raw)
	waitFor(t, "admissions", func() bool { return len(r.cap.snapshot()) >= count })
	time.Sleep(3 * durablePoll) // nothing more (e.g. a partial line) may arrive
	r.stop(t)
	return r.cap.snapshot()
}

func TestCompleteLineOffsetIgnoresReadAhead(t *testing.T) {
	drafts := runDurableTailFixture(t, "one\ntwo\npartial", 2)
	if len(drafts) != 2 {
		t.Fatalf("expected two complete lines, got %d", len(drafts))
	}
	if drafts[0].Cursor == nil || drafts[1].Cursor == nil {
		t.Fatal("missing source cursor")
	}
	if drafts[0].RawMessage != "one" || drafts[0].Cursor.Offset != 4 || drafts[1].RawMessage != "two" || drafts[1].Cursor.Offset != 8 {
		t.Fatal("checkpoint includes read-ahead or partial line")
	}
}

func TestDurableTailCursorCarriesIdentityAndLocation(t *testing.T) {
	drafts := runDurableTailFixture(t, "a\r\n\nb\n", 2)
	if len(drafts) != 2 || drafts[0].RawMessage != "a" || drafts[1].RawMessage != "b" {
		t.Fatalf("drafts %+v", drafts)
	}
	c := drafts[1].Cursor
	if !strings.HasPrefix(c.Source, fileSourcePrefix) || c.Identity == "" || c.Generation == "" || c.Offset != 6 {
		t.Fatalf("cursor %+v", c)
	}
	if drafts[0].Location != strings.TrimPrefix(c.Source, fileSourcePrefix) || drafts[0].LogType != "syslog" {
		t.Fatalf("draft %+v", drafts[0])
	}
}

func TestDurableTailFirstEnablementStartsAtEOF(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "history before enablement\n")
	r := env.tail(path, "linux_auth", nil)
	env.baselined(t, path)
	appendFile(t, path, "new\n")
	waitFor(t, "new line", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	if got := r.cap.lines(); got[0] != "new" {
		t.Fatalf("history was backfilled: %v", got)
	}
}

func TestDurableTailResumesAfterRestartWithoutSkipping(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "1\n2\n")
	waitFor(t, "first run", func() bool { return len(r.cap.lines()) == 2 })
	r.stop(t)

	appendFile(t, path, "3\n4\n") // written while the agent is down
	env.restart()
	r = env.tail(path, "syslog", nil)
	appendFile(t, path, "5\n")
	waitFor(t, "second run", func() bool { return len(r.cap.lines()) == 3 })
	time.Sleep(3 * durablePoll)
	r.stop(t)
	if got := strings.Join(r.cap.lines(), ","); got != "3,4,5" {
		t.Fatalf("after restart got %s (skipped or replayed lines)", got)
	}
}

func TestDurableTailPartialLineCompletesAcrossRestart(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "one\npart")
	waitFor(t, "complete line", func() bool { return len(r.cap.lines()) == 1 })
	time.Sleep(3 * durablePoll)
	r.stop(t)
	if len(r.cap.lines()) != 1 {
		t.Fatalf("partial line emitted at EOF: %v", r.cap.lines())
	}
	appendFile(t, path, "ial\n")
	env.restart()
	r = env.tail(path, "syslog", nil)
	waitFor(t, "completed partial line", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	if got := r.cap.lines()[0]; got != "partial" {
		t.Fatalf("got %q", got)
	}
}

func TestDurableTailOversizedLineIsCountedOnceAndSkipped(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	big := strings.Repeat("x", 3*env.opts.MaxEventBytes)
	appendFile(t, path, big+"\nafter\n")
	waitFor(t, "line after the oversized one", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	if got := r.cap.lines(); got[0] != "after" {
		t.Fatalf("got %v", got)
	}
	if loss := env.journal.Snapshot().KnownLoss["oversize"]; loss != 1 {
		t.Fatalf("oversize loss %d, want 1", loss)
	}
	env.restart() // the oversized line must not be re-read and re-counted
	r = env.tail(path, "syslog", nil)
	time.Sleep(3 * durablePoll)
	r.stop(t)
	if len(r.cap.lines()) != 0 || env.journal.Snapshot().KnownLoss["oversize"] != 1 {
		t.Fatalf("restart replayed: %v loss=%d", r.cap.lines(), env.journal.Snapshot().KnownLoss["oversize"])
	}
}

func TestDurableTailRenamedOpenFileIsDrainedThenReplacementFromStart(t *testing.T) {
	env := newTailEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "a\n")
	waitFor(t, "a", func() bool { return len(r.cap.lines()) == 1 })

	rotated := filepath.Join(dir, "app.log.1")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // the writer keeps its handle
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("b\n"); err != nil { // late write to the rotated file
		t.Fatal(err)
	}
	f.Close()
	writeFile(t, path, "c\n")
	waitFor(t, "drain and replacement", func() bool { return len(r.cap.lines()) == 3 })
	r.stop(t)
	drafts := r.cap.snapshot()
	if got := strings.Join(r.cap.lines(), ","); got != "a,b,c" {
		t.Fatalf("got %s", got)
	}
	old, repl := drafts[1].Cursor, drafts[2].Cursor
	if repl.Offset != 2 || repl.Generation == old.Generation || repl.Identity == old.Identity {
		t.Fatalf("replacement cursor %+v after %+v", repl, old)
	}
	if env.journal.Snapshot().UnknownGaps != 0 {
		t.Fatal("a drained rotation was reported as a gap")
	}
}

func TestDurableTailGlobReadsEveryArrivalFromTheStart(t *testing.T) {
	env := newTailEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "existing.log"), "history\n")
	pattern := filepath.Join(dir, "*.log")
	r := env.tail(pattern, "syslog", nil)
	env.baselined(t, filepath.Join(dir, "existing.log"))
	// two files arrive between discovery passes
	writeFile(t, filepath.Join(dir, "a.log"), "a1\na2\n")
	writeFile(t, filepath.Join(dir, "b.log"), "b1\n")
	appendFile(t, filepath.Join(dir, "existing.log"), "e1\n")
	waitFor(t, "every file", func() bool { return len(r.cap.lines()) == 4 })
	r.stop(t)
	got := map[string]bool{}
	for _, l := range r.cap.lines() {
		got[l] = true
	}
	for _, want := range []string{"a1", "a2", "b1", "e1"} {
		if !got[want] {
			t.Fatalf("missing %s in %v", want, r.cap.lines())
		}
	}
	if got["history"] {
		t.Fatal("history of a file present at enablement was backfilled")
	}
}

func TestDurableTailMissingRotatedIdentityRecordsGap(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "1\n")
	waitFor(t, "1", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	before := r.cap.snapshot()[0].Cursor

	// while stopped: rotated away and gone, a new file in its place
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "fresh\n")
	env.restart()
	r = env.tail(path, "syslog", nil)
	waitFor(t, "replacement", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	c := r.cap.snapshot()[0].Cursor
	if r.cap.lines()[0] != "fresh" || c.Offset != 6 || c.Generation == before.Generation {
		t.Fatalf("got %v %+v", r.cap.lines(), c)
	}
	if gaps := env.journal.Snapshot().UnknownGaps; gaps != 1 {
		t.Fatalf("unknown gaps %d, want 1", gaps)
	}
}

// Deleting and recreating a file while stopped can reuse its inode (CI's
// overlay filesystem does). Rewriting in place reproduces that: same identity,
// different content, size at least the committed offset.
func TestDurableTailSameIdentityDifferentContentIsANewFile(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "1\n")
	waitFor(t, "1", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	before := r.cap.snapshot()[0].Cursor

	writeFile(t, path, "fresh\n") // same inode, new content
	env.restart()
	r = env.tail(path, "syslog", nil)
	waitFor(t, "rewritten file", func() bool { return len(r.cap.lines()) == 1 })
	time.Sleep(3 * durablePoll)
	r.stop(t)
	got := r.cap.snapshot()
	if len(got) != 1 || got[0].RawMessage != "fresh" || got[0].Cursor.Generation == before.Generation {
		t.Fatalf("resumed into the middle of another file: %v", r.cap.lines())
	}
	if gaps := env.journal.Snapshot().UnknownGaps; gaps != 1 {
		t.Fatalf("unknown gaps %d, want 1", gaps)
	}
}

func TestDurableTailFingerprintCoversTheFileStart(t *testing.T) {
	drafts := runDurableTailFixture(t, strings.Repeat("y", 300)+"\nz\n", 2)
	first, second := drafts[0].Cursor.Bookmark, drafts[1].Cursor.Bookmark
	if !strings.HasPrefix(first, "fp:256:") || first != second {
		t.Fatalf("fingerprints %q %q", first, second)
	}
}

func TestDurableTailRenamedWhileStoppedResumesInGlobScope(t *testing.T) {
	env := newTailEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "app-1.log")
	writeFile(t, path, "")
	pattern := filepath.Join(dir, "app-*.log")
	r := env.tail(pattern, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "1\n")
	waitFor(t, "1", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)

	appendFile(t, path, "2\n")
	moved := filepath.Join(dir, "app-2.log")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	env.restart()
	r = env.tail(pattern, "syslog", nil)
	waitFor(t, "2", func() bool { return len(r.cap.lines()) == 1 })
	time.Sleep(3 * durablePoll)
	r.stop(t)
	if got := strings.Join(r.cap.lines(), ","); got != "2" {
		t.Fatalf("renamed file not resumed at its cursor: %s", got)
	}
	if env.journal.Snapshot().UnknownGaps != 0 {
		t.Fatal("a rename inside the glob scope was reported as a gap")
	}
}

func TestDurableTailCopytruncateRecordsGapAndRestartsFromZero(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	appendFile(t, path, "before-truncate\n")
	waitFor(t, "first line", func() bool { return len(r.cap.lines()) == 1 })
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "truncation gap", func() bool { return env.journal.Snapshot().UnknownGaps == 1 })
	appendFile(t, path, "after\n")
	waitFor(t, "line after truncation", func() bool { return len(r.cap.lines()) == 2 })
	r.stop(t)
	drafts := r.cap.snapshot()
	if drafts[1].RawMessage != "after" || drafts[1].Cursor.Offset != 6 || drafts[1].Cursor.Generation == drafts[0].Cursor.Generation {
		t.Fatalf("after truncation: %+v", drafts[1])
	}
}

func TestDurableTailDiskPressureRetriesTheSameLine(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", func(try int, d evidence.Draft) error {
		if d.RawMessage == "1" && try <= 3 {
			return evidence.ErrFull
		}
		return nil
	})
	env.baselined(t, path)
	appendFile(t, path, "1\n2\n")
	waitFor(t, "paused source", func() bool {
		return env.journal.Snapshot().Sources[fileSourcePrefix+path].State == "paused"
	})
	waitFor(t, "both lines", func() bool { return len(r.cap.lines()) == 2 })
	r.stop(t)
	if got := strings.Join(r.cap.lines(), ","); got != "1,2" {
		t.Fatalf("got %s", got)
	}
	r.cap.mu.Lock()
	tries := r.cap.tries
	r.cap.mu.Unlock()
	for _, d := range tries[:3] {
		if d.RawMessage != "1" || d.Cursor.Offset != 2 {
			t.Fatalf("retry changed the draft: %+v", d)
		}
	}
	if s := env.journal.Snapshot().Sources[fileSourcePrefix+path]; s.State != "healthy" {
		t.Fatalf("source not healthy after pressure: %+v", s)
	}
}

func TestDurableTailStopWhilePausedKeepsTheCursor(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	var full = func(int, evidence.Draft) error { return evidence.ErrFull }
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	r.stop(t)
	before, _ := env.journal.Cursor(fileSourcePrefix + path)

	r = env.tail(path, "syslog", full)
	appendFile(t, path, "stuck\n")
	waitFor(t, "paused source", func() bool {
		return env.journal.Snapshot().Sources[fileSourcePrefix+path].State == "paused"
	})
	r.stop(t) // must return promptly while paused
	after, _ := env.journal.Cursor(fileSourcePrefix + path)
	if after.Offset != before.Offset || after.Generation != before.Generation {
		t.Fatalf("cursor advanced past an unadmitted line: %+v -> %+v", before, after)
	}
	env.restart()
	r = env.tail(path, "syslog", nil)
	waitFor(t, "line after pressure", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
	if r.cap.lines()[0] != "stuck" {
		t.Fatalf("got %v", r.cap.lines())
	}
}

func TestDurableTailStorageFailureIsNotSuccess(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	failing := errors.New("disk on fire")
	r := env.tail(path, "syslog", func(try int, d evidence.Draft) error {
		if try == 1 {
			return failing
		}
		return nil
	})
	env.baselined(t, path)
	appendFile(t, path, "1\n")
	waitFor(t, "retried line", func() bool { return len(r.cap.lines()) == 1 })
	r.stop(t)
}
