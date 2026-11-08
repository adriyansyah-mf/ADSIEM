package winsensor

import (
	"slices"
	"testing"

	"github.com/siem-platform/agent/internal/etw"
)

// Kernel-File Write (16) carries no name, only the FileObject of the open
// (Create, 12) it writes through: the guard gets it as a "write" of that
// path, the SIEM gets nothing.
func TestWriteResolvedThroughItsOpen(t *testing.T) {
	tr, now := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	tr.file(kf(fileCreate, 7, "FileObject", "0xF1", "FileName", vol+`\Users\bob\Documents\q3.xlsx`))
	for i := 0; i < 20; i++ { // a big file written in chunks is one event
		if got := tr.file(kf(fileWrite, 7, "ByteOffset", "0x0", "FileObject", "0xF1", "IOSize", "0x10000")); got != nil {
			t.Fatalf("a write was shipped to the SIEM: %v", got)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("OnFile saw %d events, want 1: %+v", len(seen), seen)
	}
	w := seen[0]
	if w.Action != "write" || w.PID != 7 || w.Path != `C:\Users\bob\Documents\q3.xlsx` || w.Image != `C:\Tools\locker.exe` || w.From != "" {
		t.Fatalf("write event = %+v", w)
	}
	// Another process writing the same file is another event.
	tr.file(kf(fileCreate, 6796, "FileObject", "0xF2", "FileName", vol+`\Users\bob\Documents\q3.xlsx`))
	tr.file(kf(fileWrite, 6796, "FileObject", "0xF2"))
	// The same process, the same file, a new window: again.
	*now = now.Add(fileWindow)
	tr.file(kf(fileWrite, 7, "FileObject", "0xF1"))
	if len(seen) != 3 || seen[1].PID != 6796 || seen[2].PID != 7 {
		t.Fatalf("OnFile = %+v", seen)
	}
	// Nothing new reaches the SIEM: no lines, no summary counts.
	if got := tr.tick(); got != nil {
		t.Fatalf("tick shipped %v", got)
	}
	if got := tr.flushAll(); got != nil {
		t.Fatalf("flush shipped %v", got)
	}
}

func TestWriteDropped(t *testing.T) {
	tr, _ := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	tr.file(kf(fileCreate, 7, "FileObject", "0xA1", "FileName", vol+`\data\a.txt`))
	tr.file(kf(fileCreate, 4, "FileObject", "0xA2", "FileName", vol+`\data\b.txt`))
	tr.file(kf(fileCreate, 99, "FileObject", "0xA3", "FileName", vol+`\data\c.txt`))
	tr.file(kf(fileCreate, 7, "FileObject", "0xA4", "FileName", `\Device\NamedPipe\x`))
	for name, ev := range map[string]*etw.Event{
		"unknown FileObject":           kf(fileWrite, 7, "FileObject", "0xFFFF"),
		"no FileObject":                kf(fileWrite, 7),
		"System (lazy writer, paging)": kf(fileWrite, 4, "FileObject", "0xA2"),
		"the agent itself":             kf(fileWrite, 99, "FileObject", "0xA3"),
		"not a file on a volume":       kf(fileWrite, 7, "FileObject", "0xA4"),
	} {
		if got := tr.file(ev); got != nil {
			t.Errorf("%s: shipped %v", name, got)
		}
		if len(seen) != 0 {
			t.Errorf("%s: OnFile got %+v", name, seen)
			seen = nil
		}
	}
	// Without OnFile (no guard) writes are not even looked at.
	tr.onFile = nil
	if got := tr.file(kf(fileWrite, 7, "FileObject", "0xA1")); got != nil {
		t.Fatalf("shipped %v", got)
	}
}

// The dedupe set is bounded.
func TestWriteDedupeBounded(t *testing.T) {
	tr, _ := newTestTracker()
	n := 0
	tr.onFile = func(FileEvent) { n++ }
	tr.file(kf(fileCreate, 7, "FileObject", "0xB1", "FileName", vol+`\data\a.txt`))
	for pid := uint32(1000); pid < 1000+maxWrites+10; pid++ {
		tr.file(kf(fileWrite, pid, "FileObject", "0xB1"))
	}
	if len(tr.writes) > maxWrites || n != maxWrites+10 {
		t.Fatalf("writes map %d (max %d), events %d", len(tr.writes), maxWrites, n)
	}
}

// The WRITE keyword and event 16 are only asked of ETW when a guard listens:
// the SIEM's file events stay exactly what they were.
func TestFileProviderWritesOnlyForTheGuard(t *testing.T) {
	kw, ids := fileProvider(false)
	if kw != kernelFileKeywords || kw&writeKeyword != 0 || slices.Contains(ids, fileWrite) {
		t.Fatalf("without a guard: keywords %#x ids %v", kw, ids)
	}
	kw, ids = fileProvider(true)
	if kw != kernelFileKeywords|writeKeyword || !slices.Contains(ids, fileWrite) || len(ids) != len(fileEventIDs)+1 {
		t.Fatalf("with a guard: keywords %#x ids %v", kw, ids)
	}
	if !slices.Equal(fileEventIDs, []uint16{fileCreate, fileDeletePath, fileRenamePath, fileCreateNew}) {
		t.Fatalf("fileEventIDs changed: %v", fileEventIDs)
	}
}
