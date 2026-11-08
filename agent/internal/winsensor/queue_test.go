package winsensor

import (
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

// A flood of Kernel-File writes (they only feed the ransomware guard) never
// costs a SIEM event: writes have their own bounded queue and drop counter,
// and waiting SIEM events are handled before any write.
func TestWriteFloodLeavesSIEMEventsDelivered(t *testing.T) {
	q := newEventQueue(64, 32)
	pushFile, pushWrite := q.push(fileEvent), q.push(writeEvent)
	const siem = 50
	for i := 0; i < 10000; i++ {
		pushWrite(&etw.Event{ID: fileWrite})
		if i%200 == 0 && i/200 < siem {
			pushFile(&etw.Event{ID: fileCreateNew})
		}
	}
	if q.dropped.Load() != 0 {
		t.Fatalf("%d SIEM events dropped by a write flood", q.dropped.Load())
	}
	if q.writesDropped.Load() == 0 {
		t.Fatal("the write queue never overflowed: no flood")
	}

	var order []kind
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.loop(stop, nil, nil, loopHooks{handle: func(s source) {
			order = append(order, s.kind)
			if len(order) == siem+32 {
				close(stop)
			}
		}})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not drain the queues")
	}
	files, firstWrites := 0, 0
	for i, k := range order {
		if k == fileEvent {
			files++
			if firstWrites > 1 {
				t.Fatalf("SIEM event %d handled after %d writes: %v", i, firstWrites, order[:i+1])
			}
		} else {
			firstWrites++
		}
	}
	if files != siem {
		t.Fatalf("%d of %d SIEM events delivered", files, siem)
	}
}

// The status line counts write drops apart from SIEM drops.
func TestStatusLineCountsWriteDrops(t *testing.T) {
	l := statusLine(3, 10, 500, 9000)
	for _, want := range []string{`Dropped="3"`, `DroppedTotal="10"`, `WritesDropped="500"`, `WritesDroppedTotal="9000"`} {
		if !strings.Contains(l, want) {
			t.Errorf("%s missing from %s", want, l)
		}
	}
	if !strings.HasPrefix(l, "EventID=255 ") {
		t.Errorf("line = %s", l)
	}
}

// The write session: opens (12, decoded) name a FileObject, writes (16,
// fast-decoded: PID and the FileObject value only) are resolved through them.
func TestWriteSessionResolvesFastWrites(t *testing.T) {
	tr, _ := newTestTracker()
	var seen []FileEvent
	tr.onFile = func(e FileEvent) { seen = append(seen, e) }
	tr.writeSession(kf(fileCreate, 7, "FileObject", "0xFFFFC08A1B2C3D40", "FileName", vol+`\Users\bob\Documents\q3.xlsx`))
	tr.writeSession(&etw.Event{ID: fileWrite, PID: 7, Value: 0xFFFFC08A1B2C3D40})
	tr.writeSession(&etw.Event{ID: fileWrite, PID: 7, Value: 0xFFFFC08A1B2C3D40})
	tr.writeSession(&etw.Event{ID: fileWrite, PID: 7, Value: 0x1234}) // unknown object
	if len(seen) != 1 || seen[0].Action != "write" || seen[0].Path != `C:\Users\bob\Documents\q3.xlsx` || seen[0].PID != 7 {
		t.Fatalf("OnFile = %+v", seen)
	}
}
