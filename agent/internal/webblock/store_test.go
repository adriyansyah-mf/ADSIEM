package webblock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
)

type fakePoster struct {
	pages []string
	reqs  []map[string]any
}

func (f *fakePoster) PostContext(_ context.Context, path string, payload any) (*http.Response, error) {
	if path != Path {
		return nil, fmt.Errorf("unexpected path %s", path)
	}
	b, _ := json.Marshal(payload)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.reqs = append(f.reqs, m)
	if len(f.pages) == 0 {
		return nil, fmt.Errorf("no queued page")
	}
	body := f.pages[0]
	f.pages = f.pages[1:]
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(body))}, nil
}

func (f *fakePoster) req(t *testing.T, i int, since float64, cont bool, rules float64) {
	t.Helper()
	if i >= len(f.reqs) {
		t.Fatalf("request %d missing (have %d)", i, len(f.reqs))
	}
	r := f.reqs[i]
	if r["since"] != since || r["continuing"] != cont || r["rules"] != rules {
		t.Fatalf("request %d = %v, want since=%v continuing=%v rules=%v", i, r, since, cont, rules)
	}
}

const pol = `"policy":{"enabled":true,"page_html":"<p>b</p>","contact":"it","max_entries":100}`

func newStore(t *testing.T) *Store { return Open(filepath.Join(t.TempDir(), ListFile)) }

func TestFirstSync(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{`{"group":"g","seq":5,"reset":true,"more":false,"rules":2,"version":"g:5",` + pol + `,"changes":[
	{"domain":"a.example","action":"block","source":"manual","reason":"r"},
	{"domain":"b.example","action":"block","source":"alert"},
	{"domain":"c.example","action":"block","source":"urlhaus"}]}`}}
	var changed *List
	s.OnChange = func(l *List) { changed = l }
	if err := s.Sync(context.Background(), f, "g:5"); err != nil {
		t.Fatal(err)
	}
	f.req(t, 0, 0, false, 0)
	c := s.Current()
	if len(c.Entries) != 3 || c.Version != "g:5" || c.Seq != 5 || c.Rules != 2 || c.Group != "g" || !c.Policy.Enabled || c.Policy.PageHTML != "<p>b</p>" {
		t.Fatalf("bad list %+v", c)
	}
	if changed != c {
		t.Fatal("OnChange not called with current")
	}
	s.Want("g:5")
	if _, need := s.wanted(); need {
		t.Fatal("should not need sync")
	}
}

func TestDelta(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{
		`{"group":"g","seq":2,"reset":true,"rules":1,"version":"g:2",` + pol + `,"changes":[{"domain":"a.example","action":"block","source":"manual"},{"domain":"b.example","action":"block","source":"manual"}]}`,
		`{"group":"g","seq":4,"reset":false,"rules":1,"version":"g:4",` + pol + `,"changes":[{"domain":"c.example","action":"block","source":"alert"},{"domain":"a.example","action":"remove"}]}`,
	}}
	if err := s.Sync(context.Background(), f, "g:2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background(), f, "g:4"); err != nil {
		t.Fatal(err)
	}
	f.req(t, 1, 2, false, 1)
	c := s.Current()
	if _, ok := c.Entries["a.example"]; ok || len(c.Entries) != 2 || c.Entries["c.example"].Source != "alert" || c.Seq != 4 {
		t.Fatalf("bad list %+v", c)
	}
}

func TestPaging(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{
		`{"group":"g","seq":10,"reset":true,"more":true,"rules":4,"version":"",` + pol + `,"changes":[{"domain":"a.example","action":"block","source":"manual"}]}`,
		`{"group":"g","seq":20,"reset":false,"more":false,"rules":4,"version":"g:20",` + pol + `,"changes":[{"domain":"b.example","action":"block","source":"manual"}]}`,
	}}
	if err := s.Sync(context.Background(), f, "g:20"); err != nil {
		t.Fatal(err)
	}
	f.req(t, 0, 0, false, 0)
	f.req(t, 1, 10, true, 4)
	c := s.Current()
	if c.Version != "g:20" || c.Seq != 20 || len(c.Entries) != 2 {
		t.Fatalf("bad list %+v", c)
	}
}

func TestPagingNoPartialInstall(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{
		`{"group":"g","seq":10,"reset":true,"more":true,"rules":4,"version":"",` + pol + `,"changes":[{"domain":"a.example","action":"block","source":"manual"}]}`,
	}}
	if err := s.Sync(context.Background(), f, "g:20"); err == nil {
		t.Fatal("expected error on second page")
	}
	if c := s.Current(); c.Version != "" || len(c.Entries) != 0 {
		t.Fatalf("partial install %+v", c)
	}
}

func TestResetOnContinuingPage(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{
		`{"group":"g","seq":10,"reset":true,"more":true,"rules":4,` + pol + `,"changes":[{"domain":"old.example","action":"block","source":"manual"}]}`,
		`{"group":"g","seq":20,"reset":true,"more":true,"rules":9,` + pol + `,"changes":[{"domain":"new1.example","action":"block","source":"manual"}]}`,
		`{"group":"g","seq":30,"reset":false,"more":false,"rules":9,"version":"g:30",` + pol + `,"changes":[{"domain":"new2.example","action":"block","source":"manual"}]}`,
	}}
	if err := s.Sync(context.Background(), f, "g:30"); err != nil {
		t.Fatal(err)
	}
	f.req(t, 1, 10, true, 4)
	f.req(t, 2, 20, true, 9)
	c := s.Current()
	if _, ok := c.Entries["old.example"]; ok || len(c.Entries) != 2 || c.Rules != 9 {
		t.Fatalf("bad list %+v", c)
	}
}

func TestGroupChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), ListFile)
	old := Empty()
	old.Group, old.Seq, old.Rules, old.Version = "blue", 7, 3, "blue:7"
	old.Policy.Enabled = true
	old.Entries["blue.example"] = Entry{Source: "manual"}
	if err := old.Save(path); err != nil {
		t.Fatal(err)
	}
	s := Open(path)
	f := &fakePoster{pages: []string{
		`{"group":"red","seq":4,"reset":false,"rules":1,` + pol + `,"changes":[{"domain":"x.example","action":"block","source":"manual"}]}`,
		`{"group":"red","seq":4,"reset":true,"rules":1,"version":"red:4",` + pol + `,"changes":[{"domain":"red.example","action":"block","source":"manual"}]}`,
	}}
	if err := s.Sync(context.Background(), f, "red:4"); err != nil {
		t.Fatal(err)
	}
	f.req(t, 0, 7, false, 3)
	f.req(t, 1, 0, false, 0)
	c := s.Current()
	if c.Group != "red" || len(c.Entries) != 1 || c.Entries["red.example"].Source != "manual" {
		t.Fatalf("bad list %+v", c)
	}
}

func TestOffInstallsEmpty(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{`{"group":"g","seq":1,"reset":true,"rules":1,"version":"g:1",` + pol + `,"changes":[{"domain":"a.example","action":"block","source":"manual"}]}`}}
	if err := s.Sync(context.Background(), f, "g:1"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.OnChange = func(*List) { calls++ }
	if err := s.Sync(context.Background(), f, ""); err != nil {
		t.Fatal(err)
	}
	if c := s.Current(); c.Version != "" || len(c.Entries) != 0 || calls != 1 {
		t.Fatalf("want empty, calls=%d, %+v", calls, c)
	}
	if err := s.Sync(context.Background(), f, ""); err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestPolicyDisabledInstallsEmpty(t *testing.T) {
	s := newStore(t)
	f := &fakePoster{pages: []string{`{"group":"g","seq":0,"reset":true,"more":false,"rules":0,"version":"","policy":{"enabled":false},"changes":[]}`}}
	calls := 0
	s.OnChange = func(*List) { calls++ }
	if err := s.Sync(context.Background(), f, "g:9"); err != nil {
		t.Fatal(err)
	}
	if c := s.Current(); c.Version != "" || c.Active() || len(c.Entries) != 0 || calls != 1 {
		t.Fatalf("calls=%d %+v", calls, c)
	}
}

func TestWantedVersionCompare(t *testing.T) {
	s := newStore(t)
	if _, need := s.wanted(); need {
		t.Fatal("no want yet")
	}
	s.Want("g:1")
	if w, need := s.wanted(); !need || w != "g:1" {
		t.Fatal("expected need")
	}
}
