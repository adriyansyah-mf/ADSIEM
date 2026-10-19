package buffer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpillAppendAndDrain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spill.log")

	s, err := OpenSpill(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Append("linux_auth\x00failed login for root")
	s.Append("apache_access\x00GET / 200")
	if got := s.Count(); got != 2 {
		t.Fatalf("count=%d want 2", got)
	}

	entries := s.Drain()
	if len(entries) != 2 {
		t.Fatalf("drained %d entries, want 2", len(entries))
	}
	if !strings.Contains(entries[0], "linux_auth") {
		t.Fatalf("unexpected entry: %q", entries[0])
	}
	if got := s.Count(); got != 0 {
		t.Fatalf("spill must be empty after drain, got %d", got)
	}
}

func TestSpillPreservesMultilineEntry(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSpill(filepath.Join(dir, "spill.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	original := "syslog\x00line one\nline two"
	s.Append(original)

	entries := s.Drain()
	if len(entries) != 1 {
		t.Fatalf("multiline entry must stay a single record, got %d", len(entries))
	}
	if entries[0] != original {
		t.Fatalf("roundtrip mismatch:\n got %q\nwant %q", entries[0], original)
	}
}

func TestSpillSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spill.log")

	first, _ := OpenSpill(path)
	first.Append("a\x001")
	first.Append("b\x002")
	first.Close()

	second, err := OpenSpill(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if got := second.Count(); got != 2 {
		t.Fatalf("reopened spill lost entries: %d", got)
	}
	entries := second.Drain()
	if len(entries) != 2 || entries[1] != "b\x002" {
		t.Fatalf("unexpected drain: %v", entries)
	}
}

func TestSpillNilIsSafe(t *testing.T) {
	var s *Spill
	s.Append("x")
	if got := s.Count(); got != 0 {
		t.Fatalf("nil spill count should be 0, got %d", got)
	}
	if got := s.Drain(); got != nil {
		t.Fatalf("nil spill drain should be nil, got %v", got)
	}
}

func TestSpillCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "spill.log")
	s, err := OpenSpill(nested)
	if err != nil {
		t.Fatalf("expected nested dir creation, got %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}
