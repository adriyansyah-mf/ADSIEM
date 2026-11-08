package linsensor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// I7: fopen("wb") / Python open(p, "wb") is O_WRONLY|O_CREAT|O_TRUNC. On an
// existing file that is an in-place rewrite (what script ransomware does),
// not a new file: the guard gets "write", as Windows reports it. A file
// that the open created, or an O_EXCL open, stays "create". SIEM lines are
// unchanged (action=create, as the flags say).
func TestTruncatingOpenOfExistingFileIsARewriteForTheGuard(t *testing.T) {
	p, s, files, now := newTestProcessor(fakeProc{exe: map[uint32]string{40: "/usr/bin/python3"}})
	born := map[string]time.Time{
		"/home/u/docs/old.docx": now.Add(-48 * time.Hour), // there for two days
		"/home/u/docs/new.docx": *now,                     // created by this open
	}
	p.birth = func(path string) (time.Time, bool) { b, ok := born[path]; return b, ok }
	wb := uint64(oWronly | oCreat | oTrunc)
	p.handle(rawEvent{kind: kindOpen, tgid: 40, pid: 40, path: "/home/u/docs/old.docx", arg0: wb, comm: "python3"})
	p.handle(rawEvent{kind: kindOpen, tgid: 40, pid: 40, path: "/home/u/docs/new.docx", arg0: wb, comm: "python3"})
	p.handle(rawEvent{kind: kindOpen, tgid: 40, pid: 40, path: "/home/u/docs/old.docx", arg0: wb | oExcl, comm: "python3"})
	p.handle(rawEvent{kind: kindOpen, tgid: 40, pid: 40, path: "/home/u/docs/unknown.docx", arg0: wb, comm: "python3"})
	want := []string{"write", "create", "create", "create"}
	if len(*files) != len(want) {
		t.Fatalf("OnFile = %+v", *files)
	}
	for i, w := range want {
		if (*files)[i].Action != w {
			t.Errorf("event %d (%s): action %s, want %s", i, (*files)[i].Path, (*files)[i].Action, w)
		}
	}
	for _, l := range s.lines {
		if !contains(l, "action=create") {
			t.Errorf("SIEM line changed: %s", l)
		}
	}
}

// The real birth time (statx): a file that exists has one in the past.
func TestBirthTimeOfAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	os.WriteFile(path, []byte("x"), 0o644)
	b, ok := fileBirth(path)
	if !ok {
		t.Skip("no birth time on this filesystem")
	}
	if b.After(time.Now().Add(time.Second)) || time.Since(b) > time.Minute {
		t.Fatalf("birth %v", b)
	}
	if _, ok := fileBirth(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("birth of a missing file")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
