package yarascan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/yara"
)

const evilRule = `rule webshell : php {
  meta:
    description = "eval of request data"
    score = 85
  strings:
    $a = "eval($_POST"
  condition:
    $a
}`

type lines struct {
	mu  sync.Mutex
	got []string
}

func (l *lines) push(logType, line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, logType+" "+line)
}

func (l *lines) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.got...)
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		meta []yara.Meta
		want string
	}{
		{nil, "high"},
		{[]yara.Meta{{Key: "severity", Value: "Critical"}}, "critical"},
		{[]yara.Meta{{Key: "severity", Value: "bogus"}, {Key: "score", Value: int64(45)}}, "medium"},
		{[]yara.Meta{{Key: "score", Value: int64(80)}}, "critical"},
		{[]yara.Meta{{Key: "score", Value: "60"}}, "high"},
		{[]yara.Meta{{Key: "score", Value: int64(10)}}, "low"},
	}
	for _, c := range cases {
		if got := Severity(c.meta); got != c.want {
			t.Errorf("Severity(%v) = %s, want %s", c.meta, got, c.want)
		}
	}
}

func TestMatchLineQuoting(t *testing.T) {
	m := yara.RuleMatch{
		Rule: "r1", Namespace: `pack "x"`, Tags: []string{"a", "b"},
		Meta:    []yara.Meta{{Key: "description", Value: "two\nlines"}},
		Strings: []yara.StringMatch{{ID: "$b", Offset: 9}, {ID: "$a", Offset: 3}, {ID: "$a", Offset: 30}},
	}
	got := MatchLine(m, Rule{}, `C:\Temp\evil "1".php`, "abc", 42, "on_access")
	want := `event=yara_match rule="r1" namespace="pack \"x\"" severity=high file="C:\\Temp\\evil \"1\".php" sha256=abc size=42 tags="a,b" strings="$a@3,$b@9" trigger=on_access description="two lines"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestMatchLineCarriesRuleRevisionAndCase(t *testing.T) {
	m := yara.RuleMatch{Rule: "AI_x", Namespace: "AI_x", Meta: []yara.Meta{{Key: "case", Value: "c-1"}}}
	got := MatchLine(m, Rule{ID: "r-9", Revision: "abc123"}, "/tmp/x", "sha", 1, "on_access")
	if !strings.HasSuffix(got, ` rule_id="r-9" revision="abc123" case="c-1"`) {
		t.Fatalf("provenance missing: %s", got)
	}
}

func TestSetRulesRemembersEachRulesIDAndRevision(t *testing.T) {
	s := New(Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}})
	s.SetRules("h", []Rule{{ID: "r-9", Name: "AI_x", Revision: "abc123", Content: `rule AI_x { condition: true }`}})
	if ref := s.ref("AI_x"); ref.ID != "r-9" || ref.Revision != "abc123" {
		t.Fatalf("ref: %+v", ref)
	}
}

func TestScanPathCachesUnchangedFiles(t *testing.T) {
	var out lines
	s := New(Options{Roots: []string{t.TempDir()}, Push: out.push})
	if errs := s.SetRules("h1", []Rule{{Name: "pack", Content: evilRule}, {Name: "broken", Content: "rule {"}}); len(errs) != 1 {
		t.Fatalf("errs = %v", errs)
	}
	p := filepath.Join(t.TempDir(), "shell.php")
	os.WriteFile(p, []byte(`<?php eval($_POST["c"]); ?>`), 0o644)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := s.ScanPath(ctx, p, "on_access"); err != nil {
			t.Fatal(err)
		}
	}
	got := out.snapshot()
	if len(got) != 1 {
		t.Fatalf("an unchanged file must be scanned once, got %d lines: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "yara_match event=yara_match rule=\"webshell\" namespace=\"pack\" severity=critical") ||
		!strings.Contains(got[0], `tags="php"`) || !strings.Contains(got[0], `strings="$a@6"`) {
		t.Fatalf("line = %s", got[0])
	}
	// New rules mean a rescan.
	s.SetRules("h2", []Rule{{Name: "pack", Content: evilRule}})
	s.ScanPath(ctx, p, "on_access")
	if n := len(out.snapshot()); n != 2 {
		t.Fatalf("after a rule change: %d lines, want 2", n)
	}
}

func TestScanPathLimits(t *testing.T) {
	var out lines
	s := New(Options{MaxFileSize: 10, Push: out.push})
	s.SetRules("h", []Rule{{Name: "p", Content: evilRule}})
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	os.WriteFile(big, []byte(strings.Repeat("x", 11)), 0o644)
	if _, err := s.ScanPath(context.Background(), big, "t"); err == nil {
		t.Fatal("a file over the size limit must be skipped with an error")
	}
	link := filepath.Join(dir, "link")
	if os.Symlink(big, link) == nil {
		if m, err := s.ScanPath(context.Background(), link, "t"); err != nil || m != nil {
			t.Fatalf("symlinks are not followed: %v %v", m, err)
		}
	}
}

func TestRunScansNewFiles(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "uploads")
	os.Mkdir(sub, 0o755)
	var out lines
	s := New(Options{Roots: []string{root}, Push: out.push})
	s.SetRules("h", []Rule{{Name: "pack", Content: evilRule}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	time.Sleep(300 * time.Millisecond) // watcher set up

	os.WriteFile(filepath.Join(sub, "a.php"), []byte(`x eval($_POST[1])`), 0o644)
	newDir := filepath.Join(root, "new")
	os.Mkdir(newDir, 0o755)
	time.Sleep(300 * time.Millisecond) // new directory picked up
	os.WriteFile(filepath.Join(newDir, "b.php"), []byte(`eval($_POST[2])`), 0o644)
	os.WriteFile(filepath.Join(root, "clean.txt"), []byte("hello"), 0o644)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(out.snapshot()) < 2 {
		time.Sleep(100 * time.Millisecond)
	}
	got := out.snapshot()
	if len(got) != 2 {
		t.Fatalf("got %d match lines, want 2: %v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "a.php") || !strings.Contains(joined, "b.php") {
		t.Fatalf("lines = %v", got)
	}
}

type fakeServer struct {
	mu    sync.Mutex
	calls int
	hash  string
	rules []Rule
	fail  bool
}

func (f *fakeServer) set(fail bool) {
	f.mu.Lock()
	f.fail = fail
	f.mu.Unlock()
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeServer) PostContext(_ context.Context, path string, _ any) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if path != RulesPath {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	if f.fail {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	b, _ := json.Marshal(rulesResponse{Hash: f.hash, Rules: f.rules})
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func TestSyncLoopRetriesUntilLoaded(t *testing.T) {
	srv := &fakeServer{hash: "v1", rules: []Rule{{Name: "pack", Content: evilRule}}, fail: true}
	s := New(Options{Push: func(string, string) {}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.SyncLoop(ctx, srv)
	s.Want("v1")
	time.Sleep(200 * time.Millisecond)
	if s.Hash() != "" {
		t.Fatal("loaded rules although the server failed")
	}
	srv.set(false)
	s.Want("v1") // the next heartbeat signals again
	deadline := time.Now().Add(5 * time.Second)
	for s.Hash() != "v1" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Hash() != "v1" {
		t.Fatalf("hash = %q after the server recovered", s.Hash())
	}
	calls := srv.count()
	s.Want("v1")
	time.Sleep(100 * time.Millisecond)
	if srv.count() != calls {
		t.Fatal("refetched rules that are already loaded")
	}
	s.Want("")
	deadline = time.Now().Add(5 * time.Second)
	for s.Hash() != "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r, _ := s.current(); s.Hash() != "" || r.Len() != 0 {
		t.Fatal("rules not cleared when the server has none")
	}
}
