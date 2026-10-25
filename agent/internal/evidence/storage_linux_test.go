//go:build linux

package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxRejectsSymlinkAncestor(t *testing.T) {
	o := journalOptions(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(o.Dir, link); err != nil {
		t.Fatal(err)
	}
	o.Dir = filepath.Join(link, "evidence")
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

func TestLinuxRejectsSymlinkState(t *testing.T) {
	o := journalOptions(t)
	if err := os.Mkdir(o.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("untouched"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(o.Dir, "owner.lock")); err != nil {
		t.Fatal(err)
	}
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if err == nil {
		t.Fatal("symlink state accepted")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("outside data changed: %v", err)
	}
}

func TestLinuxRejectsHardlinkedState(t *testing.T) {
	o := journalOptions(t)
	if err := os.Mkdir(o.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(o.Dir, "owner.lock")); err != nil {
		t.Fatal(err)
	}
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if err == nil {
		t.Fatal("hardlinked state accepted")
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("outside permissions changed: %v", err)
	}
}

func TestLinuxRepairsExistingPermissions(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	paths := []string{o.Dir, firstSegment(t, o), filepath.Join(o.Dir, "owner.lock")}
	for _, path := range paths {
		if err := os.Chmod(path, 0777); err != nil {
			t.Fatal(err)
		}
	}
	openJournal(t, o)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("permissions %s: %v", path, info.Mode())
		}
	}
}
