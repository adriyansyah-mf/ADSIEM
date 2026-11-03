package fullscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/yarascan"
)

type fakeScanner struct {
	mu      sync.Mutex
	paths   []string
	trigger string
	force   bool
	delay   time.Duration
}

func (f *fakeScanner) Scan(ctx context.Context, path, trigger string, force bool) (int, error) {
	f.mu.Lock()
	f.paths = append(f.paths, path)
	f.trigger, f.force = trigger, force
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if strings.HasSuffix(path, ".evil") {
		return 1, nil
	}
	return 0, nil
}

func tree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, p := range []string{"a.txt", "sub/b.evil", "sub/deep/c.bin", "excluded/x.evil", "empty"} {
		full := filepath.Join(d, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		data := []byte("content of " + p)
		if p == "empty" {
			data = nil
		}
		os.WriteFile(full, data, 0o644)
	}
	return d
}

func TestCustomScanWalksSkipsAndCounts(t *testing.T) {
	d := tree(t)
	var lines []string
	sc := &fakeScanner{}
	s, err := Run(context.Background(), sc, Options{Kind: KindCustom, Paths: []string{d},
		Skip:      func(p string) bool { return strings.Contains(p, "excluded") },
		Push:      func(lt, l string) { lines = append(lines, lt+" "+l) },
		Requested: "dashboard"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != "completed" || s.Files != 3 || s.Detections != 1 || s.Skipped != 0 {
		t.Fatalf("summary %+v (scanned %v)", s, sc.paths)
	}
	if sc.trigger != "custom_scan" || !sc.force {
		t.Fatalf("trigger %q force %v", sc.trigger, sc.force)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "status=started") || !strings.Contains(lines[1], "status=completed") ||
		!strings.Contains(lines[1], "files=3 ") || !strings.Contains(lines[1], "detections=1 ") ||
		!strings.Contains(lines[1], `requested="dashboard"`) || !strings.HasPrefix(lines[1], LogType+" event=file_scan ") {
		t.Fatalf("lines %v", lines)
	}
}

func TestRateLimitAndCancel(t *testing.T) {
	d := t.TempDir()
	for i := 0; i < 4; i++ {
		os.WriteFile(filepath.Join(d, string(rune('a'+i))), make([]byte, 64<<10), 0o644)
	}
	start := time.Now()
	s, _ := Run(context.Background(), &fakeScanner{}, Options{Kind: KindCustom, Paths: []string{d}, RateBytes: 512 << 10})
	if s.Files != 4 || time.Since(start) < 400*time.Millisecond {
		t.Fatalf("256 KB at 512 KB/s took %s (%d files)", time.Since(start), s.Files)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sc := &fakeScanner{delay: 50 * time.Millisecond}
	go func() { time.Sleep(60 * time.Millisecond); cancel() }()
	s, err := Run(ctx, sc, Options{Kind: KindCustom, Paths: []string{d}})
	if err != nil || s.Status != "cancelled" || s.Files >= 4 {
		t.Fatalf("cancel: %+v %v", s, err)
	}
}

func TestOneScanAtATime(t *testing.T) {
	d := tree(t)
	sc := &fakeScanner{delay: 30 * time.Millisecond}
	done := make(chan struct{})
	go func() { Run(context.Background(), sc, Options{Kind: KindCustom, Paths: []string{d}}); close(done) }()
	time.Sleep(10 * time.Millisecond)
	if !Running() {
		t.Fatal("not running")
	}
	if _, err := Run(context.Background(), sc, Options{Kind: KindCustom, Paths: []string{d}}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second scan: %v", err)
	}
	<-done
	if Running() {
		t.Fatal("still running")
	}
	if _, err := Run(context.Background(), sc, Options{Kind: "deep"}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := Run(context.Background(), sc, Options{Kind: KindCustom, Paths: []string{"/no/such/dir"}}); err == nil {
		t.Fatal("no roots accepted")
	}
}

// With the real on-access scanner: a file already checked on access (so
// cached as unchanged) is still checked, and reported, by a scan.
func TestScanWithTheOnAccessScanner(t *testing.T) {
	d := t.TempDir()
	shell := filepath.Join(d, "shell.php")
	os.WriteFile(shell, []byte(`<?php eval($_POST["c"]); ?>`), 0o644)
	var lines []string
	ys := yarascan.New(yarascan.Options{Roots: []string{d}, Push: func(lt, l string) { lines = append(lines, l) }})
	ys.SetRules("h", []yarascan.Rule{{Name: "pack", Content: `rule webshell { strings: $a = "eval($_POST" condition: $a }`}})
	ys.ScanPath(context.Background(), shell, "on_access")
	s, err := Run(context.Background(), ys, Options{Kind: KindCustom, Paths: []string{d}})
	if err != nil || s.Detections != 1 || len(lines) != 2 || !strings.Contains(lines[1], "trigger=custom_scan") {
		t.Fatalf("summary %+v lines %v err %v", s, lines, err)
	}
}

func TestQuickRootsExist(t *testing.T) {
	for _, r := range Roots(KindQuick, nil) {
		if _, err := os.Stat(r); err != nil {
			t.Errorf("quick root %s: %v", r, err)
		}
	}
	if len(Roots(KindFull, nil)) == 0 {
		t.Error("no full scan roots")
	}
}
