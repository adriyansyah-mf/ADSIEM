package webblock

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// jitterRig runs a SyncLoop with a fake delay and records every pause.
type jitterRig struct {
	s      *Store
	pauses []time.Duration
	mu     sync.Mutex
	block  chan struct{} // when set, pause waits for it (or ctx)
}

func (r *jitterRig) install() {
	r.s.jitter = func() time.Duration { return 42 * time.Second }
	r.s.pause = func(ctx context.Context, d time.Duration) bool {
		r.mu.Lock()
		r.pauses = append(r.pauses, d)
		blk := r.block
		r.mu.Unlock()
		if blk != nil {
			select {
			case <-blk:
			case <-ctx.Done():
				return false
			}
		}
		return ctx.Err() == nil
	}
}

func newJitterRig(t *testing.T) *jitterRig {
	r := &jitterRig{s: newStore(t)}
	r.install()
	return r
}

func (r *jitterRig) setBlock(c chan struct{}) { r.mu.Lock(); r.block = c; r.mu.Unlock() }
func (r *jitterRig) pauseCount() int          { r.mu.Lock(); defer r.mu.Unlock(); return len(r.pauses) }

func verPage(group string, seq int, reset bool) string {
	return fmt.Sprintf(`{"group":%q,"seq":%d,"reset":%v,"rules":1,"version":"%s:%d",`, group, seq, reset, group, seq) +
		pol + `,"changes":[{"domain":"a.example","action":"block","source":"manual"}]}`
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestJitterRules(t *testing.T) {
	r := newJitterRig(t)
	f := &fakePoster{pages: []string{verPage("g", 1, true), verPage("g", 2, false), verPage("h", 1, true), verPage("h", 1, true)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.s.SyncLoop(ctx, f)

	r.s.Want("g:1")
	waitFor(t, "g:1", func() bool { return r.s.Current().Version == "g:1" })
	if r.pauseCount() != 0 {
		t.Fatal("first sync must not wait")
	}
	r.s.Want("g:2")
	waitFor(t, "g:2", func() bool { return r.s.Current().Version == "g:2" })
	if r.pauseCount() != 1 || r.pauses[0] != 42*time.Second {
		t.Fatalf("pauses %v", r.pauses)
	}
	r.s.Want("h:1")
	waitFor(t, "h:1", func() bool { return r.s.Current().Version == "h:1" })
	if r.pauseCount() != 1 {
		t.Fatalf("group change must be immediate, pauses %v", r.pauses)
	}
}

func TestJitterNotForActivation(t *testing.T) {
	r := newJitterRig(t)
	f := &fakePoster{pages: []string{verPage("g", 1, true), verPage("g", 3, true)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.s.SyncLoop(ctx, f)
	r.s.Want("g:1")
	waitFor(t, "g:1", func() bool { return r.s.Current().Version == "g:1" })
	r.s.Want("") // off
	waitFor(t, "off", func() bool { return r.s.Current().Version == "" })
	r.s.Want("g:3") // "" -> non-empty
	waitFor(t, "g:3", func() bool { return r.s.Current().Version == "g:3" })
	if r.pauseCount() != 0 {
		t.Fatalf("pauses %v", r.pauses)
	}
}

func TestJitterNotOnFirstSyncWithSavedList(t *testing.T) {
	dir := t.TempDir()
	l := Empty()
	l.Version, l.Group, l.Seq, l.Policy = "g:1", "g", 1, Policy{Enabled: true}
	if err := l.Save(ListPath(dir)); err != nil {
		t.Skip("cannot save a list here:", err)
	}
	r := &jitterRig{s: Open(ListPath(dir))}
	r.install()
	if r.s.Current().Version != "g:1" {
		t.Skip("saved list not loadable here")
	}
	f := &fakePoster{pages: []string{verPage("g", 2, false)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.s.SyncLoop(ctx, f)
	r.s.Want("g:2")
	waitFor(t, "g:2", func() bool { return r.s.Current().Version == "g:2" })
	if r.pauseCount() != 0 {
		t.Fatal("first sync after start must not wait")
	}
}

func TestJitterCancelledOnShutdown(t *testing.T) {
	r := newJitterRig(t)
	f := &fakePoster{pages: []string{verPage("g", 1, true), verPage("g", 2, false)}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.s.SyncLoop(ctx, f); close(done) }()
	r.s.Want("g:1")
	waitFor(t, "g:1", func() bool { return r.s.Current().Version == "g:1" })
	r.setBlock(make(chan struct{})) // never released
	r.s.Want("g:2")
	waitFor(t, "pause", func() bool { return r.pauseCount() == 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SyncLoop did not stop during the delay")
	}
	if r.s.Current().Version != "g:1" || len(f.reqs) != 1 {
		t.Fatalf("synced after shutdown: %s reqs %d", r.s.Current().Version, len(f.reqs))
	}
}

func TestJitterNewerWantDuringDelaySyncsOnce(t *testing.T) {
	r := newJitterRig(t)
	f := &fakePoster{pages: []string{verPage("g", 1, true), verPage("g", 3, false)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.s.SyncLoop(ctx, f)
	r.s.Want("g:1")
	waitFor(t, "g:1", func() bool { return r.s.Current().Version == "g:1" })
	rel := make(chan struct{})
	r.setBlock(rel)
	r.s.Want("g:2")
	waitFor(t, "pause", func() bool { return r.pauseCount() == 1 })
	r.s.Want("g:3") // a newer heartbeat during the delay
	close(rel)
	waitFor(t, "g:3", func() bool { return r.s.Current().Version == "g:3" })
	time.Sleep(50 * time.Millisecond)
	if len(f.reqs) != 2 || r.pauseCount() != 1 {
		t.Fatalf("reqs %d pauses %d", len(f.reqs), r.pauseCount())
	}
}

func TestGroupOf(t *testing.T) {
	for in, want := range map[string]string{"g:5": "g", "a:b:7": "a:b", "": "", "x": "x"} {
		if got := groupOf(in); got != want {
			t.Errorf("groupOf(%q) = %q, want %q", in, got, want)
		}
	}
}
