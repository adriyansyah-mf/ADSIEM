package tailer

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/evidence"
)

func burst(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "burst line %04d\n", i)
	}
	return b.String()
}

// A burst is admitted in group commits (a flush per batch, not per line), in
// order, and the cursor ends just past the last line.
func TestDurableTailAdmitsABurstInGroupCommits(t *testing.T) {
	env := newTailEnv(t)
	env.opts.MaxBytes = 4 << 20
	env.restart()
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	r := env.tail(path, "syslog", nil)
	env.baselined(t, path)
	content := burst(1000)
	began := time.Now()
	appendFile(t, path, content)
	// NTFS flushes are slow on CI runners: allow time, and on failure say
	// whether it was slow (lines still arriving) or stuck.
	for len(r.cap.lines()) < 1000 {
		if time.Since(began) > time.Minute {
			r.cap.mu.Lock()
			commits := len(r.cap.batches)
			r.cap.mu.Unlock()
			t.Fatalf("after %s: %d of 1000 lines in %d commits", time.Since(began), len(r.cap.lines()), commits)
		}
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(began)
	r.stop(t)

	for i, line := range r.cap.lines() {
		if want := fmt.Sprintf("burst line %04d", i); line != want {
			t.Fatalf("line %d is %q, want %q", i, line, want)
		}
	}
	r.cap.mu.Lock()
	batches := append([]int(nil), r.cap.batches...)
	r.cap.mu.Unlock()
	t.Logf("1000 lines admitted in %s, %d commits %v", elapsed, len(batches), batches)
	if len(batches) > 100 {
		t.Fatalf("1000 lines took %d commits: not grouped", len(batches))
	}
	if c, _ := env.journal.Cursor(fileSourcePrefix + path); c.Offset != int64(len(content)) {
		t.Fatalf("cursor at %d, file is %d bytes", c.Offset, len(content))
	}
}

// A failure in the middle of a batch admits the lines before it, keeps the
// cursor there, and the rest arrives on retry: nothing skipped, nothing twice.
func TestDurableTailBatchFailureResumesAtTheFailedLine(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	failed := false
	r := env.tail(path, "syslog", func(_ int, d evidence.Draft) error {
		if d.RawMessage == "burst line 0030" && !failed {
			failed = true
			return evidence.ErrFull // disk pressure: retried
		}
		return nil
	})
	env.baselined(t, path)
	appendFile(t, path, burst(60))
	waitFor(t, "60 lines", func() bool { return len(r.cap.lines()) == 60 })
	r.stop(t)
	got := r.cap.lines()
	for i, line := range got {
		if want := fmt.Sprintf("burst line %04d", i); line != want {
			t.Fatalf("line %d is %q, want %q (all: %d)", i, line, want, len(got))
		}
	}
	if !failed {
		t.Fatal("the failure was never injected")
	}
}
