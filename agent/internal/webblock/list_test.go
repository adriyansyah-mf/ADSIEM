package webblock

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSelectedCapAndPriority(t *testing.T) {
	l := Empty()
	l.Policy.MaxEntries = 3
	l.Entries = map[string]Entry{
		"z.example": {Source: "manual"},
		"b.example": {Source: "manual"},
		"m.example": {Source: "alert"},
		"a.example": {Source: "urlhaus"},
		"c.example": {Source: "phishtank"},
	}
	want := []string{"b.example", "z.example", "m.example"}
	if got := l.Selected(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Selected = %v, want %v", got, want)
	}
}

func TestSelectedDefaultCap(t *testing.T) {
	l := Empty()
	for i := 0; i < 50010; i++ {
		l.Entries[fmt.Sprintf("d%06d.example", i)] = Entry{Source: "urlhaus"}
	}
	if got := len(l.Selected()); got != 50000 {
		t.Fatalf("len = %d, want 50000", got)
	}
}

func TestActive(t *testing.T) {
	l := Empty()
	if l.Active() {
		t.Fatal("empty list active")
	}
	l.Version, l.Policy.Enabled = "g:1", true
	if !l.Active() {
		t.Fatal("expected active")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	l := Empty()
	l.Version, l.Group, l.Seq, l.Rules = "g:3", "g", 3, 7
	l.Policy = Policy{Enabled: true, PageHTML: "<p>x</p>", Contact: "it@x", MaxEntries: 10}
	l.Entries["bad.example"] = Entry{Source: "manual", Reason: "r"}
	p := ListPath(t.TempDir())
	if err := l.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, l) {
		t.Fatalf("round trip: %+v != %+v", got, l)
	}
	missing := filepath.Join(t.TempDir(), "missing.json")
	if _, err := Load(missing); err == nil {
		t.Fatal("expected error for missing file")
	}
	if s := Open(missing); s.Current().Version != "" || s.Current().Entries == nil {
		t.Fatal("Open should fall back to Empty")
	}
}
