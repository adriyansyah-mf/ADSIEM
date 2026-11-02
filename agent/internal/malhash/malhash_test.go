package malhash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha(c string) string { return strings.Repeat(c, 64) }

func TestSetApplyLookupAndLabels(t *testing.T) {
	s := Empty().apply(true, [][]string{{sha("a"), "AgentTesla"}, {sha("B"), "Emotet"}, {sha("c"), "AgentTesla"},
		{"nothex", "x"}, {}})
	if s.Len() != 3 || len(s.table) != 2 {
		t.Fatalf("len=%d labels=%v", s.Len(), s.table)
	}
	if l, ok := s.Lookup(strings.ToUpper(sha("a"))); !ok || l != "AgentTesla" {
		t.Fatalf("lookup a: %q %v", l, ok)
	}
	if _, ok := s.Lookup(sha("d")); ok {
		t.Fatal("unknown hash found")
	}
	if _, ok := s.Lookup("abc"); ok {
		t.Fatal("short hash found")
	}
	s2 := s.apply(false, [][]string{{sha("a")}, {sha("d"), "Mirai"}})
	if _, ok := s2.Lookup(sha("a")); ok || s2.Len() != 3 {
		t.Fatalf("removal/add wrong: %d", s2.Len())
	}
	if _, ok := s.Lookup(sha("a")); !ok {
		t.Fatal("apply changed the old snapshot")
	}
	if s.Active() {
		t.Fatal("a set with no action is not active")
	}
	if n := New(ActionBlock, map[string]string{sha("e"): ""}); !n.Active() || !n.Block() {
		t.Fatal("New block set")
	}
	var nilSet *Set
	if _, ok := nilSet.Lookup(sha("a")); ok || nilSet.Active() || nilSet.Block() {
		t.Fatal("nil set must be inert")
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FileName)
	s := New(ActionDetect, map[string]string{sha("1"): "x", sha("2"): "y"})
	s.Seq, s.Version = 42, "42:detect"
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 42 || got.Version != "42:detect" || got.Action != ActionDetect || got.Len() != 2 {
		t.Fatalf("loaded %+v", got)
	}
	if l, ok := got.Lookup(sha("2")); !ok || l != "y" {
		t.Fatal("lookup after load")
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("damaged file loaded")
	}
	if st := Open(path); st.Current().Active() {
		t.Fatal("a damaged file must give an empty set")
	}
}

type fakeServer struct {
	pages []page
	reqs  []map[string]any
	err   error
}

func (f *fakeServer) PostContext(_ context.Context, path string, payload any) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.reqs = append(f.reqs, payload.(map[string]any))
	p := f.pages[0]
	f.pages = f.pages[1:]
	b, _ := json.Marshal(p)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func TestStoreSyncPagesAndOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	st := Open(path)
	var changed []*Set
	st.OnChange = func(s *Set) { changed = append(changed, s) }
	srv := &fakeServer{pages: []page{
		{Action: "detect", Seq: 2, Reset: true, More: true, Changes: [][]string{{sha("1"), "a"}, {sha("2"), "b"}}},
		{Action: "detect", Seq: 3, More: true, Changes: [][]string{{sha("3"), "c"}}},
		{Action: "detect", Version: "4:detect", Seq: 4, Changes: [][]string{{sha("1")}}},
	}}
	if err := st.Sync(context.Background(), srv, "4:detect"); err != nil {
		t.Fatal(err)
	}
	cur := st.Current()
	if cur.Len() != 2 || cur.Seq != 4 || cur.Version != "4:detect" || !cur.Active() || len(changed) != 1 {
		t.Fatalf("after sync: len=%d seq=%d version=%q changed=%d", cur.Len(), cur.Seq, cur.Version, len(changed))
	}
	if srv.reqs[0]["since"] != int64(0) || srv.reqs[0]["continuing"] != false ||
		srv.reqs[1]["since"] != int64(2) || srv.reqs[1]["continuing"] != true {
		t.Fatalf("requests: %v", srv.reqs)
	}
	if reopened := Open(path); reopened.Current().Len() != 2 || reopened.Current().Seq != 4 {
		t.Fatal("not saved")
	}
	if _, need := st.wanted(); need {
		t.Fatal("nothing wanted yet")
	}
	st.Want("4:detect")
	if _, need := st.wanted(); need {
		t.Fatal("already at the wanted version")
	}

	// the next delta starts from the saved seq
	srv.pages = []page{{Action: "block", Version: "5:block", Seq: 5, Changes: [][]string{{sha("9"), "z"}}}}
	if err := st.Sync(context.Background(), srv, "5:block"); err != nil {
		t.Fatal(err)
	}
	if srv.reqs[3]["since"] != int64(4) || srv.reqs[3]["continuing"] != false || !st.Current().Block() || st.Current().Len() != 3 {
		t.Fatalf("delta: %v block=%v len=%d", srv.reqs[3], st.Current().Block(), st.Current().Len())
	}

	// off on the server: dropped
	if err := st.Sync(context.Background(), srv, ""); err != nil {
		t.Fatal(err)
	}
	if st.Current().Active() || st.Current().Len() != 0 || len(changed) != 3 {
		t.Fatal("off must drop the set")
	}

	// a failed fetch keeps what we have
	st.cur.Store(New(ActionDetect, map[string]string{sha("7"): ""}))
	srv.err = errors.New("down")
	if err := st.Sync(context.Background(), srv, "9:detect"); err == nil || st.Current().Len() != 1 {
		t.Fatal("a failed sync must keep the current set")
	}
}

func TestFileCheckerReportsAndQuarantines(t *testing.T) {
	st := Open(filepath.Join(t.TempDir(), FileName))
	var lines []string
	var quarantined []string
	fc := &FileChecker{Store: st, Push: func(lt, l string) {
		if lt != LogType {
			t.Fatalf("log type %q", lt)
		}
		lines = append(lines, l)
	}, Quarantine: func(p string) error { quarantined = append(quarantined, p); return nil }}

	fc.Check("/tmp/x", sha("1"), 10) // nothing loaded yet
	st.cur.Store(New(ActionDetect, map[string]string{sha("1"): "Mirai"}))
	fc.Check("/tmp/x", sha("1"), 10)
	fc.Check("/tmp/x", sha("1"), 10) // same file and content: once a minute
	fc.Check("/tmp/y", sha("2"), 10) // not known
	if len(lines) != 1 || len(quarantined) != 0 {
		t.Fatalf("detect: lines=%v quarantined=%v", lines, quarantined)
	}
	want := `event=known_malware action=detected trigger=file label="Mirai" sha256=` + sha("1") +
		` path="/tmp/x" engine=on_access size=10`
	if lines[0] != want {
		t.Fatalf("line:\n%s\nwant\n%s", lines[0], want)
	}

	st.cur.Store(New(ActionBlock, map[string]string{sha("2"): ""}))
	fc.Check("/tmp/y", sha("2"), 5)
	if len(quarantined) != 1 || !strings.Contains(lines[1], "action=quarantined") || !strings.Contains(lines[1], `label="unknown"`) {
		t.Fatalf("block: %v %v", lines, quarantined)
	}
	fc.Quarantine = func(string) error { return errors.New("read-only") }
	fc.Check("/tmp/z", sha("2"), 5)
	if !strings.Contains(lines[2], `action=detected`) || !strings.Contains(lines[2], `error="read-only"`) {
		t.Fatalf("failed quarantine: %s", lines[2])
	}
}

func TestEventLineExec(t *testing.T) {
	l := Event{Action: "terminated", Trigger: "exec", Label: `Agent "T"`, SHA256: sha("f"), Path: `C:\Users\a\x.exe`,
		Parent: `C:\Windows\explorer.exe`, Engine: "etw", PID: 10, PPID: 4}.Line()
	for _, part := range []string{`action=terminated`, `label="Agent \"T\""`, `path="C:\\Users\\a\\x.exe"`,
		`parent="C:\\Windows\\explorer.exe"`, `pid=10 ppid=4 uid=0`} {
		if !strings.Contains(l, part) {
			t.Fatalf("%q missing in %s", part, l)
		}
	}
}
