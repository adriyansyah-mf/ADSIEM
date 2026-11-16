package yarascan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const highRule = `rule shady {
  meta:
    severity = "high"
  strings:
    $a = "shady-marker"
  condition:
    $a
}`

type quarantines struct {
	mu    sync.Mutex
	paths []string
	whom  []Writer
}

func (q *quarantines) lock(path string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.paths = append(q.paths, path)
	return nil
}

func (q *quarantines) seen(path string, w Writer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.whom = append(q.whom, w)
	return w.PID != 0
}

func (q *quarantines) has(path string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range q.paths {
		if p == path {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestMatchQuarantinesAtThePolicyThreshold(t *testing.T) {
	var out lines
	var q quarantines
	min := "critical"
	s := New(Options{Roots: []string{t.TempDir()}, Push: out.push, Quarantine: q.lock, OnQuarantined: q.seen,
		Action: func(string) (string, string) { return "quarantine", min }})
	s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}, {Name: "pack2", Content: highRule}})
	dir := t.TempDir()
	shell := filepath.Join(dir, "shell.php")
	os.WriteFile(shell, []byte(`<?php eval($_POST["c"]); ?>`), 0o644)
	shady := filepath.Join(dir, "shady.txt")
	os.WriteFile(shady, []byte("shady-marker"), 0o644)
	ctx := context.Background()

	s.ScanPath(ctx, shell, TriggerOnAccess) // critical >= critical
	s.ScanPath(ctx, shady, TriggerOnAccess) // high < critical
	if !q.has(shell) || q.has(shady) {
		t.Fatalf("quarantined %v; want only the critical match", q.paths)
	}
	got := strings.Join(out.snapshot(), "\n")
	if !strings.Contains(got, "shell.php") || !strings.Contains(got, "action=quarantined") {
		t.Fatalf("critical match line: %s", got)
	}
	if !strings.Contains(got, `shady.txt" sha256=`) {
		t.Fatalf("high match must still be reported: %s", got)
	}
	for _, l := range out.snapshot() {
		if strings.Contains(l, "shady.txt") && !strings.Contains(l, "action=detected") {
			t.Fatalf("below the threshold the file is only detected: %s", l)
		}
	}

	// threshold high: the high rule quarantines too
	min = "high"
	os.WriteFile(shady, []byte("shady-marker again"), 0o644)
	s.ScanPath(ctx, shady, TriggerOnAccess)
	if !q.has(shady) {
		t.Fatal("threshold high must quarantine a high match")
	}
}

func TestDetectPolicyNeverQuarantines(t *testing.T) {
	var out lines
	var q quarantines
	s := New(Options{Roots: []string{t.TempDir()}, Push: out.push, Quarantine: q.lock,
		Action: func(string) (string, string) { return "detect", "critical" }})
	s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}})
	p := filepath.Join(t.TempDir(), "shell.php")
	os.WriteFile(p, []byte(`eval($_POST[1])`), 0o644)
	s.ScanPath(context.Background(), p, TriggerOnAccess)
	if len(q.paths) != 0 || !strings.Contains(strings.Join(out.snapshot(), ""), "action=detected") {
		t.Fatalf("detect: quarantined %v, lines %v", q.paths, out.snapshot())
	}
}

func TestLargeFileIsHashedAndScannedHeadAndTail(t *testing.T) {
	var out lines
	var hashed []string
	s := New(Options{MaxFileSize: 64, MaxPartialSize: 1 << 20, Push: out.push,
		OnHash: func(path, sum string, size int64, _ string) bool {
			hashed = append(hashed, path)
			if size != 4096 {
				t.Errorf("size %d, want the whole file", size)
			}
			return false
		}})
	s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}})
	dir := t.TempDir()
	pad := strings.Repeat("A", 4096-len("eval($_POST"))
	head := filepath.Join(dir, "padded_head.bin")
	os.WriteFile(head, []byte("eval($_POST"+pad), 0o644)
	tail := filepath.Join(dir, "padded_tail.bin")
	os.WriteFile(tail, []byte(pad+"eval($_POST"), 0o644)
	middle := filepath.Join(dir, "middle.bin")
	os.WriteFile(middle, []byte(pad[:2000]+"eval($_POST"+pad[2000:]), 0o644)
	ctx := context.Background()
	for _, p := range []string{head, tail, middle} {
		if _, err := s.ScanPath(ctx, p, TriggerOnAccess); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	got := strings.Join(out.snapshot(), "\n")
	if !strings.Contains(got, "padded_head.bin") || !strings.Contains(got, "part=head") {
		t.Fatalf("head match: %s", got)
	}
	if !strings.Contains(got, "padded_tail.bin") || !strings.Contains(got, "part=tail") {
		t.Fatalf("tail match: %s", got)
	}
	if strings.Contains(got, "middle.bin") {
		t.Fatalf("the middle of a large file is not scanned: %s", got)
	}
	if len(hashed) != 3 {
		t.Fatalf("every large file is hashed whole: %v", hashed)
	}
}

func TestSensorFileOutsideRootsScannedWhenItCanRun(t *testing.T) {
	var out lines
	s := New(Options{Roots: []string{t.TempDir()}, Push: out.push})
	s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, "Run", s.running.Load)

	elsewhere := t.TempDir()
	payload := filepath.Join(elsewhere, "payload") // no extension, ELF magic
	os.WriteFile(payload, []byte("\x7fELF....eval($_POST[x])"), 0o755)
	notes := filepath.Join(elsewhere, "notes.txt") // data: left alone even when it matches
	os.WriteFile(notes, []byte("eval($_POST[x])"), 0o644)
	logf := filepath.Join(elsewhere, "app.log")
	os.WriteFile(logf, []byte("eval($_POST[x])"), 0o644)
	w := Writer{PID: 4242, Image: "/tmp/dropper"}
	s.ObserveFile(payload, w)
	s.ObserveFile(notes, w)
	s.ObserveFile(logf, w)

	waitFor(t, "payload scanned", func() bool { return strings.Contains(strings.Join(out.snapshot(), ""), "payload") })
	time.Sleep(2500 * time.Millisecond) // the others had their chance
	got := strings.Join(out.snapshot(), "\n")
	if !strings.Contains(got, "writer_pid=4242") || !strings.Contains(got, `writer_image="/tmp/dropper"`) {
		t.Fatalf("the writer travels with the match: %s", got)
	}
	if strings.Contains(got, "notes.txt") || strings.Contains(got, "app.log") {
		t.Fatalf("data files outside the roots are not scanned: %s", got)
	}
}

func TestObserveBeforeRunIsANoOp(t *testing.T) {
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}})
	s.ObserveFile("/tmp/x.exe", Writer{})
	s.ScanExec("/tmp/x.exe", "")
	if s.Lost() != 0 || len(s.pending) != 0 || len(s.hi) != 0 {
		t.Fatal("feeds must do nothing while the scanner is not running")
	}
}

func TestFullQueueLosesOnlyOtherFilesAndCountsThem(t *testing.T) {
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}})
	for i := 0; i < loQueue+10; i++ {
		s.offer(job{path: "/data/file.txt", trigger: TriggerOnAccess})
	}
	if s.Lost() != 10 {
		t.Fatalf("lost = %d, want 10", s.Lost())
	}
	s.offer(job{path: "/tmp/stage2.exe", trigger: TriggerOnAccess})
	s.offer(job{path: "/tmp/x", trigger: TriggerExec})
	if len(s.hi) != 2 || s.Lost() != 10 {
		t.Fatalf("programs go to their own queue: hi=%d lost=%d", len(s.hi), s.Lost())
	}
	if j, ok := s.next(); !ok || j.path != "/tmp/stage2.exe" {
		t.Fatalf("programs are taken first: %+v", j)
	}
}

func TestSensorBurstIsNotCountedAsLost(t *testing.T) {
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}})
	for i := 0; i < hiQueue+loQueue+50; i++ {
		s.offer(job{path: "/home/a/build/out.js", trigger: TriggerOnAccess, filter: true})
	}
	if s.Lost() != 0 || s.dropped.Load() == 0 {
		t.Fatalf("a sensor burst is logged, not lost: lost=%d dropped=%d", s.Lost(), s.dropped.Load())
	}
	// a sensor file without an extension waits on the low queue for its first bytes
	s2 := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}})
	s2.offer(job{path: "/home/a/blob", trigger: TriggerOnAccess, filter: true})
	if len(s2.hi) != 0 || len(s2.lo) != 1 {
		t.Fatalf("hi=%d lo=%d", len(s2.hi), len(s2.lo))
	}
}

func TestNewRulesRescanRecentFilesInTheRoots(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "dropped_yesterday.php")
	os.WriteFile(old, []byte("shady-marker"), 0o644)
	var out lines
	s := New(Options{Roots: []string{root}, Push: out.push})
	s.SetRules("h1", []Rule{{Name: "pack", Content: evilRule}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, "Run", s.running.Load)
	time.Sleep(300 * time.Millisecond)
	if len(out.snapshot()) != 0 {
		t.Fatalf("no rule knows the file yet: %v", out.snapshot())
	}
	s.SetRules("h2", []Rule{{Name: "pack", Content: evilRule}, {Name: "new", Content: highRule}})
	waitFor(t, "rescan match", func() bool {
		return strings.Contains(strings.Join(out.snapshot(), ""), "trigger=rescan")
	})
	if !strings.Contains(strings.Join(out.snapshot(), ""), "dropped_yesterday.php") {
		t.Fatalf("lines: %v", out.snapshot())
	}
}

func TestInvalidateChecksUnchangedFilesAgain(t *testing.T) {
	n := 0
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {},
		OnHash: func(string, string, int64, string) bool { n++; return false }})
	p := filepath.Join(t.TempDir(), "x.bin")
	os.WriteFile(p, []byte("abc"), 0o644)
	ctx := context.Background()
	s.ScanPath(ctx, p, TriggerOnAccess)
	s.ScanPath(ctx, p, TriggerOnAccess)
	s.Invalidate() // new known-malware hashes
	s.ScanPath(ctx, p, TriggerOnAccess)
	if n != 2 {
		t.Fatalf("hash checks = %d, want 2 (once, then again after Invalidate)", n)
	}
}

func TestExecChecksAnUnchangedProgramOnce(t *testing.T) {
	n := 0
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {},
		OnHash: func(string, string, int64, string) bool { n++; return false }})
	p := filepath.Join(t.TempDir(), "tool")
	os.WriteFile(p, []byte("\x7fELF tool"), 0o755)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		s.scan(ctx, job{path: p, trigger: TriggerExec}, false)
	}
	if n != 1 {
		t.Fatalf("hash checks = %d, want 1", n)
	}
}

func TestCheckExecRefusesWhatItQuarantined(t *testing.T) {
	var q quarantines
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}, Quarantine: q.lock,
		IsQuarantined: q.has, Action: func(string) (string, string) { return "quarantine", "critical" }})
	s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}})
	dir := t.TempDir()
	bad := filepath.Join(dir, "stage2")
	os.WriteFile(bad, []byte("\x7fELF eval($_POST[1])"), 0o755)
	good := filepath.Join(dir, "tool")
	os.WriteFile(good, []byte("\x7fELF fine"), 0o755)
	ctx := context.Background()
	// read through another name, as the fanotify descriptor link is
	via := filepath.Join(dir, "via")
	os.Symlink(bad, via)
	if !s.CheckExec(ctx, bad, via) {
		t.Fatal("a program the scan quarantined must be refused")
	}
	if s.CheckExec(ctx, good, "") {
		t.Fatal("a clean program runs")
	}
	if runtime.GOOS != "windows" && s.CheckExec(ctx, "/usr/bin/true", "") {
		t.Fatal("a program the OS owns is not checked")
	}
}

func TestCandidates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	for p, want := range map[string]bool{
		"/tmp/x.exe": true, "/home/a/payload": true, "/var/log/syslog.log": false, "/proc/1/status": false,
		"/dev/null": false, "/dev/shm/x": true, "/home/a/.cache/x.sqlite": false, "/home/a/dl.crdownload": false,
		// package managers, builds, browser caches, the OS's own folders: left to the exec checks
		"/home/a/proj/node_modules/left-pad/index.js": false, "/usr/bin/ls": false,
		"/home/a/.cache/google-chrome/Default/Cache/f_000123": false, "/var/lib/docker/overlay2/x/bin/sh": false,
		"/usr/lib/python3/dist-packages/x.py": false, "/home/a/.cache/miner": true, "/usr/local/bin/x": true,
	} {
		if got := SensorCandidate(p); got != want {
			t.Errorf("SensorCandidate(%s) = %v", p, got)
		}
	}
	for p, want := range map[string]bool{"/tmp/a.ps1": true, "/tmp/payload": true, "/tmp/.hidden": false,
		"/tmp/report.pdf": false, "/var/www/s.php": true} {
		if got := Runnable(p); got != want {
			t.Errorf("Runnable(%s) = %v", p, got)
		}
	}
	if !Interesting("/x/blob.dat", []byte("MZ\x90\x00")) || !Interesting("/x/a.docm", nil) ||
		Interesting("/x/notes.txt", []byte("hello")) {
		t.Error("Interesting")
	}
	for p, want := range map[string]bool{"/usr/bin/ls": true, "/usr/local/bin/x": false, "/tmp/x": false,
		"/opt/app/bin": false, "/lib/x86_64-linux-gnu/libc.so.6": true} {
		if got := SystemProgram(p); got != want {
			t.Errorf("SystemProgram(%s) = %v", p, got)
		}
	}
	for p, want := range map[string]bool{"/tmp/dropper": true, "/dev/shm/x": true,
		"/home/a/Downloads/setup": true, "/usr/bin/curl": false, "/opt/google/chrome/chrome": false, "": false} {
		if got := DropperLocation(p); got != want {
			t.Errorf("DropperLocation(%s) = %v", p, got)
		}
	}
}
