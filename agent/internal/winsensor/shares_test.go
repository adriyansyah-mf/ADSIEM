package winsensor

import (
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/etw"
)

// I6: files on SMB shares come as \Device\Mup\server\share\... (mapped
// drives through the LanmanRedirector under Mup). The guard sees them as
// \\server\share\...; the SIEM lines stay as they were (none for shares).
func TestShareDevicePathsReachTheGuard(t *testing.T) {
	tr, _ := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	for _, c := range []struct{ device, want string }{
		{`\Device\Mup\fs01\share\dept\a.docx`, `\\fs01\share\dept\a.docx`},
		{`\Device\Mup\;LanmanRedirector\;Z:000000000001a2b3\fs01\share\x.docx`, `\\fs01\share\x.docx`},
		{`\Device\LanmanRedirector\;Z:000000000001a2b3\fs01\share\y.xlsx`, `\\fs01\share\y.xlsx`},
	} {
		seen = nil
		if got := tr.file(kf(fileCreateNew, 7, "FileName", c.device)); got != nil {
			t.Errorf("%s: shipped to the SIEM: %v", c.device, got)
		}
		if len(seen) != 1 || seen[0].Path != c.want || seen[0].Action != "create" {
			t.Errorf("%s: OnFile = %+v, want %s", c.device, seen, c.want)
		}
	}
	// A rename on a share, and writes through a share open.
	seen = nil
	tr.file(kf(fileCreate, 7, "FileObject", "0x51", "FileName", `\Device\Mup\fs01\share\q.docx`))
	if got := tr.file(kf(fileRenamePath, 7, "FileObject", "0x51", "FilePath", `\Device\Mup\fs01\share\q.docx.lck`)); got != nil {
		t.Errorf("rename shipped: %v", got)
	}
	tr.writeSession(kf(fileCreate, 7, "FileObject", "0x52", "FileName", `\Device\Mup\fs01\share\w.pdf`))
	tr.writeSession(wr(7, 0x52))
	if len(seen) != 2 || seen[0].Path != `\\fs01\share\q.docx.lck` || seen[0].From != `\\fs01\share\q.docx` ||
		seen[1].Action != "write" || seen[1].Path != `\\fs01\share\w.pdf` {
		t.Fatalf("OnFile = %+v", seen)
	}
	// Named pipes and other devices stay out.
	seen = nil
	tr.file(kf(fileCreateNew, 7, "FileName", `\Device\NamedPipe\x`))
	tr.file(kf(fileCreateNew, 7, "FileName", `\Device\Mup\fs01\PIPE\srvsvc`))
	if len(seen) != 0 {
		t.Fatalf("pipes reached the guard: %+v", seen)
	}
	// A rename from a share to a local drive keeps its SIEM line (the target
	// is local), without the share source, as before; the guard gets both.
	seen = nil
	tr.file(kf(fileCreate, 7, "FileObject", "0x53", "FileName", `\Device\Mup\fs01\share\m.txt`))
	got := tr.file(kf(fileRenamePath, 7, "FileObject", "0x53", "FilePath", vol+`\data\m.txt`))
	if len(got) != 1 || strings.Contains(got[0].line, "fs01") || !strings.Contains(got[0].line, `TargetFilename="C:\data\m.txt"`) {
		t.Fatalf("SIEM line = %v", got)
	}
	if len(seen) != 1 || seen[0].From != `\\fs01\share\m.txt` {
		t.Fatalf("OnFile = %+v", seen)
	}
}

// I8: the write session's opens have their own queue: a write flood cannot
// drop them, and the names they carry survive to resolve the writes.
func TestWriteFloodKeepsOpens(t *testing.T) {
	q := newEventQueue(64, 32)
	push := q.push(writeEvent)
	for i := 0; i < 5000; i++ {
		push(&etw.Event{ID: fileWrite, PID: 7, Value: 0xC0})
		if i%200 == 0 { // 25 opens, under the opens queue size, among 5000 writes
			push(kf(fileCreate, 7, "FileObject", "0xC0", "FileName", vol+`\Users\bob\Documents\a.docx`))
		}
	}
	if q.opensDropped.Load() != 0 || q.writesDropped.Load() == 0 {
		t.Fatalf("opens dropped %d, writes dropped %d", q.opensDropped.Load(), q.writesDropped.Load())
	}
	tr, _ := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	stop := make(chan struct{})
	done := make(chan struct{})
	n := 0
	go func() {
		defer close(done)
		q.loop(stop, nil, nil, loopHooks{handle: func(s source) {
			tr.writeSession(s.ev)
			if n++; n == 25+32 {
				close(stop)
			}
		}})
	}()
	<-done
	if len(seen) != 1 || seen[0].Path != `C:\Users\bob\Documents\a.docx` {
		t.Fatalf("writes not resolved after the flood: %+v", seen)
	}
}

// I8: the FileObject map ages out by generation, not by a full reset: the
// objects of the previous generation still resolve.
func TestWriteObjectsTwoGenerations(t *testing.T) {
	tr, _ := newTestTracker()
	n := 0
	tr.onFile = func(FileEvent) { n++ }
	for i := 0; i < maxObjects+10; i++ {
		tr.writeSession(kf(fileCreate, 7, "FileObject", "0x"+strings.ToUpper(strconvHex(uint64(i+1))), "FileName", vol+`\data\f.txt`))
	}
	tr.writeSession(wr(8, uint64(maxObjects-5))) // filled before the rollover
	tr.writeSession(wr(9, uint64(maxObjects+5))) // after it
	if n != 2 {
		t.Fatalf("%d of 2 writes resolved across a generation", n)
	}
	if tr.unresolvedWrites != 0 {
		t.Fatalf("unresolved = %d", tr.unresolvedWrites)
	}
	tr.writeSession(wr(10, 0xDEADBEEF))
	if tr.unresolvedWrites != 1 {
		t.Fatalf("an unknown object not counted: %d", tr.unresolvedWrites)
	}
}

func strconvHex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var b []byte
	for ; v > 0; v >>= 4 {
		b = append([]byte{digits[v&15]}, b...)
	}
	return string(b)
}

// I4: the status line reports what makes writes unreliable, apart from
// queue drops: opens dropped, writes through unknown objects, fast/TDH
// mismatches and whether the fast decode was switched off.
func TestStatusLineWriteHealth(t *testing.T) {
	l := statusLine(status{dropped: 1, droppedTotal: 2, writes: 3, writesTotal: 4, opens: 5,
		unresolved: 6, fastMismatches: 7, fastOff: true})
	for _, want := range []string{`Dropped="1"`, `DroppedTotal="2"`, `WritesDropped="3"`, `WritesDroppedTotal="4"`,
		`OpensDropped="5"`, `WritesUnresolved="6"`, `FastMismatches="7"`, `FastDecodeOff="true"`} {
		if !strings.Contains(l, want) {
			t.Errorf("%s missing from %s", want, l)
		}
	}
}
