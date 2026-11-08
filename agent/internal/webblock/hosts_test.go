package webblock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newHosts(t *testing.T, content string) (*HostsFile, *int) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	n := 0
	return &HostsFile{Path: p, Flush: func() error { n++; return nil }}, &n
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRenderBlock(t *testing.T) {
	if RenderBlock(nil, false) != "" {
		t.Fatal("empty list must render nothing")
	}
	got := RenderBlock([]string{"evil.example", "www.other.example"}, false)
	want := BlockBegin + "\n" +
		"127.84.0.1 evil.example\n127.84.0.1 www.evil.example\n" +
		"127.84.0.1 www.other.example\n" + BlockEnd + "\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	v6 := RenderBlock([]string{"evil.example"}, true)
	if !strings.Contains(v6, "::1 evil.example\n") || !strings.Contains(v6, "::1 www.evil.example\n") {
		t.Fatalf("missing ipv6 lines:\n%s", v6)
	}
	if strings.Contains(got, "::1") {
		t.Fatal("ipv6 lines without ipv6")
	}
}

func TestRenderBlockRejectsInjection(t *testing.T) {
	got := RenderBlock([]string{
		"evil.example\n127.0.0.1 bank.example",
		"bad domain.example",
		"UPPER.example",
		"good.example",
		"nodot",
		strings.Repeat("a", 250) + ".com",
	}, false)
	if strings.Contains(got, "bank.example") || strings.Contains(got, "bad") ||
		strings.Contains(got, "UPPER") || strings.Contains(got, "nodot") || strings.Contains(got, "aaaa") {
		t.Fatalf("invalid domains leaked:\n%s", got)
	}
	if !strings.Contains(got, "127.84.0.1 good.example\n") {
		t.Fatalf("valid domain missing:\n%s", got)
	}
	if n := strings.Count(got, "\n"); n != 4 { // begin, 2 lines, end
		t.Fatalf("unexpected line count %d:\n%s", n, got)
	}
}

func TestApplyPreservesForeignLinesLFAndCRLF(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		orig := "127.0.0.1 localhost" + eol + "# custom  line\t" + eol + eol + "10.0.0.5 nas" + eol
		h, _ := newHosts(t, orig)
		tampered, err := h.Apply([]string{"evil.example"}, false)
		if err != nil || tampered {
			t.Fatalf("apply: %v tampered=%v", err, tampered)
		}
		got := readFile(t, h.Path)
		if !strings.HasPrefix(got, orig) {
			t.Fatalf("foreign lines changed (eol %q):\n%q", eol, got)
		}
		if eol == "\r\n" && strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\n") {
			t.Fatalf("bare LF in CRLF file: %q", got)
		}
		if !strings.Contains(got, "127.84.0.1 www.evil.example"+eol) {
			t.Fatalf("missing entry: %q", got)
		}
		if err := h.Remove(); err != nil {
			t.Fatal(err)
		}
		if readFile(t, h.Path) != orig {
			t.Fatalf("removal not identical (eol %q): %q", eol, readFile(t, h.Path))
		}
	}
}

func TestApplyIdempotentNoRewrite(t *testing.T) {
	h, flushed := newHosts(t, "127.0.0.1 localhost\n")
	if _, err := h.Apply([]string{"evil.example"}, true); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(h.Path, old, old); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(h.Path)
	if _, err := h.Apply([]string{"evil.example"}, true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(h.Path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("file rewritten although unchanged")
	}
	if *flushed != 1 {
		t.Fatalf("flush calls = %d, want 1", *flushed)
	}
	if _, err := h.Apply([]string{"evil.example", "two.example"}, true); err != nil {
		t.Fatal(err)
	}
	if *flushed != 2 {
		t.Fatalf("flush calls = %d, want 2", *flushed)
	}
	if _, err := os.Stat(h.Path + ".adsiem.tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}

func TestApplyKeepsFileMode(t *testing.T) {
	h, _ := newHosts(t, "127.0.0.1 localhost\n")
	if err := os.Chmod(h.Path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Apply([]string{"evil.example"}, false); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(h.Path)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
}

func TestApplyMissingFileErrors(t *testing.T) {
	h := &HostsFile{Path: filepath.Join(t.TempDir(), "nope")}
	if _, err := h.Apply([]string{"evil.example"}, false); err == nil {
		t.Fatal("want error for missing hosts file")
	}
	if err := h.Remove(); err != nil {
		t.Fatalf("remove of missing file: %v", err)
	}
}

func TestApplyEmptyListRemovesBlock(t *testing.T) {
	orig := "127.0.0.1 localhost\n"
	h, _ := newHosts(t, orig)
	if _, err := h.Apply([]string{"evil.example"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Apply(nil, false); err != nil {
		t.Fatal(err)
	}
	if readFile(t, h.Path) != orig {
		t.Fatalf("got %q", readFile(t, h.Path))
	}
}

func TestTamperedMissingEnd(t *testing.T) {
	h, _ := newHosts(t, "127.0.0.1 localhost\n"+BlockBegin+"\n127.84.0.1 old.example\n10.0.0.5 nas\n")
	tampered, err := h.Apply([]string{"evil.example"}, false)
	if err != nil || !tampered {
		t.Fatalf("tampered=%v err=%v", tampered, err)
	}
	got := readFile(t, h.Path)
	if strings.Count(got, BlockBegin) != 1 || strings.Count(got, BlockEnd) != 1 {
		t.Fatalf("not a single block:\n%s", got)
	}
	if !strings.Contains(got, "10.0.0.5 nas\n") || strings.Contains(got, "old.example") {
		t.Fatalf("repair wrong:\n%s", got)
	}
}

func TestTamperedTwoBlocks(t *testing.T) {
	blk := BlockBegin + "\n127.84.0.1 a.example\n" + BlockEnd + "\n"
	h, _ := newHosts(t, "127.0.0.1 localhost\n"+blk+"10.0.0.5 nas\n"+blk)
	tampered, err := h.Apply([]string{"evil.example"}, false)
	if err != nil || !tampered {
		t.Fatalf("tampered=%v err=%v", tampered, err)
	}
	got := readFile(t, h.Path)
	if strings.Count(got, BlockBegin) != 1 || strings.Contains(got, "a.example") ||
		!strings.Contains(got, "10.0.0.5 nas\n") {
		t.Fatalf("repair wrong:\n%s", got)
	}
	if tampered, _ = h.Apply([]string{"evil.example"}, false); tampered {
		t.Fatal("still tampered after repair")
	}
}

func TestOrphanEndRepaired(t *testing.T) {
	h, _ := newHosts(t, "127.0.0.1 localhost\n::1 localhost\n127.84.0.1 old.example\n127.84.0.1 www.old.example\n"+BlockEnd+"\n10.0.0.5 nas\n")
	tampered, err := h.Apply([]string{"evil.example"}, false)
	if err != nil || !tampered {
		t.Fatalf("tampered=%v err=%v", tampered, err)
	}
	got := readFile(t, h.Path)
	if strings.Contains(got, "old.example") || strings.Count(got, BlockBegin) != 1 || strings.Count(got, BlockEnd) != 1 {
		t.Fatalf("not repaired:\n%s", got)
	}
	if !strings.HasPrefix(got, "127.0.0.1 localhost\n::1 localhost\n") || !strings.Contains(got, "10.0.0.5 nas\n") {
		t.Fatalf("foreign lines damaged:\n%s", got)
	}
	if tampered, _ = h.Apply([]string{"evil.example"}, false); tampered {
		t.Fatal("still tampered")
	}
}

func TestRenderBlockDedupesWWW(t *testing.T) {
	got := RenderBlock([]string{"x.example", "www.x.example"}, false)
	if c := strings.Count(got, "127.84.0.1 www.x.example\n"); c != 1 {
		t.Fatalf("www line count %d:\n%s", c, got)
	}
}

func TestReplaceBlockCleanReportsNoTamper(t *testing.T) {
	out, had, tam := ReplaceBlock("a\n", RenderBlock([]string{"x.example"}, false))
	if had || tam {
		t.Fatalf("had=%v tam=%v", had, tam)
	}
	_, had, tam = ReplaceBlock(out, "")
	if !had || tam {
		t.Fatalf("had=%v tam=%v", had, tam)
	}
}
