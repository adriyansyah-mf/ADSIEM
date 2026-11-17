package ransomguard

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

func TestOnStoppedGetsWhenAndWhereTheProcessWrote(t *testing.T) {
	dir := t.TempDir()
	docs, pics := filepath.Join(dir, "docs"), filepath.Join(dir, "pics")
	var out sink
	got := make(chan Stopped, 1)
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, Kill: true, OnStopped: func(s Stopped) { got <- s }})
	g.response = func(uint32) (int, error) { return 1, nil }
	g.can.plant()
	first := time.Now().Add(-2 * time.Minute)
	ev := linsensor.FileEvent{PID: 77, PPID: 1, UID: 1000, Image: "/tmp/.x/crypt", Comm: "crypt"}
	ev.Action, ev.Path, ev.Time = "write", filepath.Join(docs, "a.docx"), first
	g.Observe(ev)
	ev.Action, ev.From, ev.Path, ev.Time = "rename", filepath.Join(pics, "b.jpg"), filepath.Join(pics, "b.jpg.locked"), first.Add(time.Minute)
	g.Observe(ev)
	canary := filepath.Join(dir, ".siem-canary.pdf")
	ev.Action, ev.From, ev.Path, ev.Time = "rename", canary, canary+".locked", time.Now()
	g.Observe(ev)
	select {
	case s := <-got:
		if s.PID != 77 || !s.Since.Equal(first) {
			t.Fatalf("stopped %+v", s)
		}
		want := map[string]bool{docs: true, pics: true, dir: true}
		for _, d := range s.Dirs {
			delete(want, d)
		}
		if len(want) != 0 {
			t.Fatalf("dirs %v missing %v", s.Dirs, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnStopped not called")
	}
}

func TestOnStoppedNotCalledWithoutAKill(t *testing.T) {
	dir := t.TempDir()
	var out sink
	called := make(chan bool, 1)
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, Kill: false, OnStopped: func(Stopped) { called <- true }})
	g.can.plant()
	canary := filepath.Join(dir, ".siem-canary.pdf")
	g.Observe(linsensor.FileEvent{Action: "rename", From: canary, Path: canary + ".locked", PID: 9, Image: "/tmp/x", Time: time.Now()})
	out.wait(t, 1)
	select {
	case <-called:
		t.Fatal("report-only mode must not roll back")
	case <-time.After(200 * time.Millisecond):
	}
}
