package winsensor

import (
	"slices"
	"testing"

	"github.com/siem-platform/agent/internal/etw"
)

// wr is a Kernel-File Write as the write session's fast decode gives it:
// the header PID and the FileObject value, no properties.
func wr(pid uint32, obj uint64) *etw.Event {
	return &etw.Event{ID: fileWrite, PID: pid, Value: obj}
}

// Kernel-File Write (16) carries no name, only the FileObject of the open
// (Create, 12) it writes through: the guard gets it as a "write" of that
// path, the SIEM gets nothing.
func TestWriteResolvedThroughItsOpen(t *testing.T) {
	tr, now := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	tr.writeSession(kf(fileCreate, 7, "FileObject", "0xF1", "FileName", vol+`\Users\bob\Documents\q3.xlsx`))
	for i := 0; i < 20; i++ { // a big file written in chunks is one event
		tr.writeSession(wr(7, 0xF1))
	}
	if len(seen) != 1 {
		t.Fatalf("OnFile saw %d events, want 1: %+v", len(seen), seen)
	}
	w := seen[0]
	if w.Action != "write" || w.PID != 7 || w.Path != `C:\Users\bob\Documents\q3.xlsx` || w.Image != `C:\Tools\locker.exe` || w.From != "" {
		t.Fatalf("write event = %+v", w)
	}
	// Another process writing the same file is another event.
	tr.writeSession(kf(fileCreate, 6796, "FileObject", "0xF2", "FileName", vol+`\Users\bob\Documents\q3.xlsx`))
	tr.writeSession(wr(6796, 0xF2))
	// The same process, the same file, a new window: again.
	*now = now.Add(fileWindow)
	tr.writeSession(wr(7, 0xF1))
	if len(seen) != 3 || seen[1].PID != 6796 || seen[2].PID != 7 {
		t.Fatalf("OnFile = %+v", seen)
	}
	// Nothing reaches the SIEM: the write session's opens are not lines
	// (the SIEM session reports its own), no summary counts.
	if got := tr.tick(); got != nil {
		t.Fatalf("tick shipped %v", got)
	}
	if got := tr.flushAll(); got != nil {
		t.Fatalf("flush shipped %v", got)
	}
	// A write reaching the SIEM session's handler is ignored.
	if got := tr.file(kf(fileWrite, 7, "FileObject", "0xF1")); got != nil {
		t.Fatalf("shipped %v", got)
	}
}

func TestWriteDropped(t *testing.T) {
	tr, _ := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	tr.writeSession(kf(fileCreate, 7, "FileObject", "0xA1", "FileName", vol+`\data\a.txt`))
	tr.writeSession(kf(fileCreate, 4, "FileObject", "0xA2", "FileName", vol+`\data\b.txt`))
	tr.writeSession(kf(fileCreate, 99, "FileObject", "0xA3", "FileName", vol+`\data\c.txt`))
	tr.writeSession(kf(fileCreate, 7, "FileObject", "0xA4", "FileName", `\Device\NamedPipe\x`))
	for name, ev := range map[string]*etw.Event{
		"unknown FileObject":           wr(7, 0xFFFF),
		"no FileObject":                wr(7, 0),
		"System (lazy writer, paging)": wr(4, 0xA2),
		"the agent itself":             wr(99, 0xA3),
		"not a file on a volume":       wr(7, 0xA4),
	} {
		tr.writeSession(ev)
		if len(seen) != 0 {
			t.Errorf("%s: OnFile got %+v", name, seen)
			seen = nil
		}
	}
	// Without OnFile (no guard) writes are not even looked at.
	tr.onFile = nil
	tr.writeSession(wr(7, 0xA1))
}

// The dedupe set is bounded.
func TestWriteDedupeBounded(t *testing.T) {
	tr, _ := newTestTracker()
	n := 0
	tr.onFile = func(FileEvent) { n++ }
	tr.writeSession(kf(fileCreate, 7, "FileObject", "0xB1", "FileName", vol+`\data\a.txt`))
	for pid := uint32(1000); pid < 1000+maxWrites+10; pid++ {
		tr.writeSession(wr(pid, 0xB1))
	}
	if len(tr.writes) > maxWrites || n != maxWrites+10 {
		t.Fatalf("writes map %d (max %d), events %d", len(tr.writes), maxWrites, n)
	}
}

// The SIEM's Kernel-File session is exactly what it was; writes have their
// own session (opens and writes, the write fast-decoded at FileObject:
// after ByteOffset and Irp).
func TestWriteSessionConfig(t *testing.T) {
	if kernelFileKeywords&writeKeyword != 0 ||
		!slices.Equal(fileEventIDs, []uint16{fileCreate, fileDeletePath, fileRenamePath, fileCreateNew}) {
		t.Fatalf("SIEM session changed: keywords %#x ids %v", kernelFileKeywords, fileEventIDs)
	}
	p, fast := writeProvider()
	if p.GUID != kernelFileProvider || p.Keywords&writeKeyword == 0 || p.Keywords&0x80 == 0 ||
		!slices.Equal(p.EventIDs, []uint16{fileCreate, fileWrite}) {
		t.Fatalf("write provider = %+v", p)
	}
	if len(fast) != 1 || fast[0].ID != fileWrite || fast[0].Offset(8) != 16 || fast[0].Offset(4) != 12 {
		t.Fatalf("fast = %+v", fast)
	}
}
