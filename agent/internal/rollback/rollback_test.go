package rollback

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, p string, data []byte, mt time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func text(word string, n int) []byte { return bytes.Repeat([]byte(word+" "), n) }

func TestRestoreUndoesWhatRansomwareDid(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "Documents")
	other := filepath.Join(root, "Pictures")
	store := &Store{Dir: filepath.Join(t.TempDir(), "rollback"), Roots: []string{root}}
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)

	files := map[string][]byte{
		"report.docx":  text("report", 2000),
		"budget.xlsx":  text("budget", 2000),
		"notes.txt":    text("notes", 2000),
		"deleted.txt":  text("deleted", 2000),
		"stomped.pdf":  text("stomped", 2000),
		"edited.txt":   text("edited", 2000),
		"untouched.md": text("untouched", 2000),
	}
	for n, b := range files {
		write(t, filepath.Join(docs, n), b, old)
	}
	write(t, filepath.Join(other, "holiday.jpg"), text("photo", 2000), old)

	st, err := store.Snapshot()
	if err != nil || st.Copied != 8 || st.Linked != 0 {
		t.Fatalf("first snapshot: %+v %v", st, err)
	}

	// a user edit after the snapshot but before the attack: kept
	userEdit := text("edited-by-user", 3000)
	write(t, filepath.Join(docs, "edited.txt"), userEdit, time.Now().Add(-time.Hour))

	time.Sleep(10 * time.Millisecond)
	since := time.Now() // the attack starts after the snapshot
	attack := since.Add(time.Second)
	// in place
	write(t, filepath.Join(docs, "report.docx"), random(20000), attack)
	// encrypted and renamed
	write(t, filepath.Join(docs, "budget.xlsx.locked"), random(20000), attack)
	os.Remove(filepath.Join(docs, "budget.xlsx"))
	// deleted
	os.Remove(filepath.Join(docs, "deleted.txt"))
	// encrypted, modification time put back
	write(t, filepath.Join(docs, "stomped.pdf"), random(20000), old)
	// a ransom note: not a renamed copy of anything, left alone
	write(t, filepath.Join(docs, "README_DECRYPT.txt"), []byte("pay"), attack)
	// another folder the process did not write in: not touched
	write(t, filepath.Join(other, "holiday.jpg"), random(20000), attack)

	res := store.Restore([]string{docs}, since)
	if len(res.Errors) != 0 || len(res.Failed) != 0 {
		t.Fatalf("restore: %+v", res)
	}
	for _, n := range []string{"report.docx", "budget.xlsx", "deleted.txt", "stomped.pdf", "notes.txt", "untouched.md"} {
		got, err := os.ReadFile(filepath.Join(docs, n))
		if err != nil || !bytes.Equal(got, files[n]) {
			t.Errorf("%s not restored (%v)", n, err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(docs, "edited.txt")); !bytes.Equal(got, userEdit) {
		t.Error("a user's edit before the attack was rolled back")
	}
	if _, err := os.Stat(filepath.Join(docs, "budget.xlsx.locked")); !os.IsNotExist(err) {
		t.Error("the renamed encrypted copy was left in place")
	}
	if _, err := os.Stat(filepath.Join(docs, "README_DECRYPT.txt")); err != nil {
		t.Error("an unrelated new file was moved")
	}
	if got, _ := os.ReadFile(filepath.Join(other, "holiday.jpg")); bytes.Equal(got, text("photo", 2000)) {
		t.Error("a folder outside the restore was touched")
	}
	if len(res.Restored) != 4 || res.Displaced != 3 { // report, budget, deleted, stomped; report, stomped, .locked
		t.Errorf("restored %d %v displaced %d", len(res.Restored), res.Restored, res.Displaced)
	}
	// the displaced copies are kept
	n := 0
	filepath.WalkDir(filepath.Join(store.Dir, "displaced"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if n != 3 {
		t.Errorf("displaced files kept: %d", n)
	}
	if line := res.Line(4242, "/tmp/locker", since); !strings.Contains(line, "restored=4 displaced=3 failed=0") {
		t.Errorf("line: %s", line)
	}
}

func TestSnapshotsLinkUnchangedFilesAndPrune(t *testing.T) {
	root := t.TempDir()
	store := &Store{Dir: filepath.Join(t.TempDir(), "rollback"), Roots: []string{root}, Keep: 2}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	write(t, filepath.Join(root, "a.txt"), text("a", 10), old)
	write(t, filepath.Join(root, "b.txt"), text("b", 10), old)
	write(t, filepath.Join(root, "big.bin"), make([]byte, 128), old)
	store.MaxFile = 100 // big.bin is too large the first time
	if st, err := store.Snapshot(); err != nil || st.Copied != 2 || st.Skipped != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	store.MaxFile = 0
	write(t, filepath.Join(root, "b.txt"), text("b2", 10), old.Add(time.Minute))
	time.Sleep(10 * time.Millisecond)
	st, err := store.Snapshot()
	if err != nil || st.Linked != 1 || st.Copied != 2 {
		t.Fatalf("second: %+v %v", st, err)
	}
	time.Sleep(10 * time.Millisecond)
	if st, _ := store.Snapshot(); st.Linked != 3 || st.Removed != 1 {
		t.Fatalf("third: %+v", st)
	}
	if len(store.Snapshots()) != 2 {
		t.Fatalf("kept %d snapshots", len(store.Snapshots()))
	}
}

func TestNoSnapshotBeforeTheAttack(t *testing.T) {
	root := t.TempDir()
	store := &Store{Dir: filepath.Join(t.TempDir(), "rollback"), Roots: []string{root}}
	write(t, filepath.Join(root, "x.txt"), []byte("x"), time.Now())
	store.Snapshot()
	res := store.Restore([]string{root}, time.Now().Add(-time.Hour))
	if !res.Snapshot.IsZero() || len(res.Errors) != 1 || len(res.Restored) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestTheStoreIsNeverSnapshotted(t *testing.T) {
	root := t.TempDir()
	store := &Store{Dir: filepath.Join(root, "state", "rollback"), Roots: []string{root}}
	write(t, filepath.Join(root, "doc.txt"), []byte("doc"), time.Now())
	store.Snapshot()
	st, _ := store.Snapshot()
	if st.Files != 1 {
		t.Fatalf("the store copied itself: %+v", st)
	}
}

func TestMirrorKeepsTheVolume(t *testing.T) {
	if got := mirror("/s", "/home/a/x.txt"); got != filepath.Join("/s", "home/a/x.txt") {
		t.Fatalf("%s", got)
	}
}
