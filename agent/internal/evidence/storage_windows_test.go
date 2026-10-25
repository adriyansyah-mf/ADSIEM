//go:build windows

package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDirectoryPinnedAgainstRename(t *testing.T) {
	o := journalOptions(t)
	openJournal(t, o)
	if err := os.Rename(o.Dir, o.Dir+"-moved"); err == nil {
		t.Fatal("pinned directory renamed")
	}
}

func TestWindowsExistingStateACLRestricted(t *testing.T) {
	o := journalOptions(t)
	j := openJournal(t, o)
	if err := j.Append(context.Background(), journalEvent(t, o)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	paths := []string{o.Dir, firstSegment(t, o), filepath.Join(o.Dir, "owner.lock")}
	broad, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	broadACL, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, broadACL, nil); err != nil {
			t.Fatal(err)
		}
	}
	j = openJournal(t, o)
	for _, path := range paths {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := sd.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("unprotected ACL %s: %v", path, err)
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatalf("missing restricted ACL: %v", err)
		}
		// Windows adds the auto-inherited flag (D:PAI) when it applies a
		// protected DACL; compare the entries, not the flag spelling.
		if got, want := daclEntries(sd.String()), daclEntries(j.dir.security.String()); got != want {
			t.Fatalf("broad or unexpected ACL: %s, want entries %s", sd.String(), want)
		}
	}
}

// Native release gate measures the volume flush cost of namespace transitions.
func BenchmarkWindowsJournalNamespace(b *testing.B) {
	root := b.TempDir()
	i := 0
	for b.Loop() {
		o := Options{Dir: filepath.Join(root, fmt.Sprint(i)), AgentID: "11111111-1111-4111-8111-111111111111", MaxBytes: 1 << 20, SegmentBytes: 64 << 10, ReservedBytes: 16 << 10, MaxEventBytes: 4096}
		j, err := Open(o)
		if err != nil {
			b.Fatal(err)
		}
		if err := j.Close(); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func TestWindowsRejectsReparseDirectory(t *testing.T) {
	o := journalOptions(t)
	link := filepath.Join(t.TempDir(), "link")
	// Native acceptance runs elevated: creating a directory link must succeed.
	if err := os.Symlink(filepath.Dir(o.Dir), link); err != nil {
		t.Fatal(err)
	}
	o.Dir = filepath.Join(link, "journal")
	j, err := Open(o)
	if j != nil {
		j.Close()
	}
	if err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("reparse traversal accepted: %v", err)
	}
}

// daclEntries is the ACE list of an SDDL string, without owner or DACL flags.
func daclEntries(sddl string) string {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return ""
	}
	d := sddl[i+2:]
	if j := strings.IndexByte(d, '('); j >= 0 {
		return d[j:]
	}
	return d
}
