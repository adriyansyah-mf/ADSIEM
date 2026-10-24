package winevent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is an in-memory channel. Bookmarks are "bm:<record>", events are
// handles numbered by record ID; every handle it hands out must be closed.
type fakeAPI struct {
	mu        sync.Mutex
	records   []uint64 // retained record IDs, oldest first
	open      map[handle]string
	nextH     handle
	bookmarks map[handle]uint64
	events    map[handle]uint64
	flags     uint32
	start     uint64 // record the subscription starts after (bookmark mode)
	failSub   error
	failNext  error
	badRender map[uint64]bool
	badXML    map[uint64]bool
	unparsed  bool // createBookmark rejects the saved XML
}

func newFake(records ...uint64) *fakeAPI {
	return &fakeAPI{records: records, open: map[handle]string{}, bookmarks: map[handle]uint64{},
		events: map[handle]uint64{}, badRender: map[uint64]bool{}, badXML: map[uint64]bool{}}
}

func (f *fakeAPI) alloc(kind string) handle {
	f.nextH++
	f.open[f.nextH] = kind
	return f.nextH
}

func (f *fakeAPI) leaks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for h, kind := range f.open {
		out = append(out, fmt.Sprintf("%s#%d", kind, h))
	}
	return out
}

type fakeSub struct {
	f   *fakeAPI
	h   handle
	pos int // index into records of the next event to deliver
}

func (f *fakeAPI) subscribe(channel string, bookmark handle, flags uint32) (subscription, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSub != nil {
		return nil, f.failSub
	}
	f.flags = flags
	s := &fakeSub{f: f, h: f.alloc("subscription")}
	if flags&0xff == subscribeStartAfterBookmark {
		f.start = f.bookmarks[bookmark]
		found := false
		for i, r := range f.records {
			if r == f.start {
				s.pos, found = i+1, true
			}
		}
		if !found && flags&subscribeStrict != 0 {
			f.close(s.h)
			return nil, errNotFound
		}
	}
	return s, nil
}

func (s *fakeSub) wait(time.Duration) error { return nil }

func (s *fakeSub) next(max int) ([]handle, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if s.f.failNext != nil {
		return nil, s.f.failNext
	}
	var out []handle
	for ; s.pos < len(s.f.records) && len(out) < max; s.pos++ {
		h := s.f.alloc("event")
		s.f.events[h] = s.f.records[s.pos]
		out = append(out, h)
	}
	return out, nil
}

func (s *fakeSub) close() { s.f.close(s.h) }

func (f *fakeAPI) renderXML(h handle) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.events[h]
	if f.badRender[r] {
		return "", errors.New("render failed")
	}
	if f.badXML[r] {
		return "<not-an-event", nil
	}
	return fmt.Sprintf(`<Event><System><Provider Name="Test"/><EventID>701</EventID><EventRecordID>%d</EventRecordID><Channel>T</Channel></System><EventData><Data Name="n">%d</Data></EventData></Event>`, r, r), nil
}

func (f *fakeAPI) createBookmark(xml string) (handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.alloc("bookmark")
	if xml != "" {
		var r uint64
		if f.unparsed || !strings.HasPrefix(xml, "bm:") {
			f.close(h)
			return 0, errors.New("invalid bookmark XML")
		}
		fmt.Sscanf(xml, "bm:%d", &r)
		f.bookmarks[h] = r
	}
	return h, nil
}

func (f *fakeAPI) updateBookmark(bm, ev handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.open[ev]; !ok {
		return errors.New("event handle already closed")
	}
	f.bookmarks[bm] = f.events[ev]
	return nil
}

func (f *fakeAPI) renderBookmark(bm handle) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("bm:%d", f.bookmarks[bm]), nil
}

func (f *fakeAPI) latest(string) (handle, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) == 0 {
		return 0, false, nil
	}
	h := f.alloc("event")
	f.events[h] = f.records[len(f.records)-1]
	return h, true, nil
}

func (f *fakeAPI) close(h handle) {
	if h != 0 {
		delete(f.open, h)
	}
}

// closeLocked-free wrapper for the interface
type lockedFake struct{ *fakeAPI }

func (l lockedFake) close(h handle) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fakeAPI.close(h)
}

// collect subscribes and returns events until n arrived (then cancels).
func collect(t *testing.T, f *fakeAPI, resume Resume, n int, emitErr func(Event) error) ([]Event, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got []Event
	err := subscribeResume(ctx, lockedFake{f}, "T", resume, func(ev Event) error {
		if emitErr != nil {
			if err := emitErr(ev); err != nil {
				return err
			}
		}
		got = append(got, ev)
		if len(got) == n {
			cancel()
		}
		return nil
	})
	if leaks := f.leaks(); len(leaks) != 0 {
		t.Fatalf("handles left open: %v", leaks)
	}
	return got, err
}

func TestBaselineBookmarksNewestEventOrReportsEmpty(t *testing.T) {
	f := newFake()
	r, err := baseline(lockedFake{f}, "T")
	if err != nil || !r.Empty || !r.Initialized || r.Bookmark != "" {
		t.Fatalf("empty channel: %+v %v", r, err)
	}
	f = newFake(5, 6, 7)
	r, err = baseline(lockedFake{f}, "T")
	if err != nil || r.Empty || !r.Initialized || r.Bookmark != "bm:7" {
		t.Fatalf("retained history: %+v %v", r, err)
	}
	if leaks := f.leaks(); len(leaks) != 0 {
		t.Fatalf("baseline leaked %v", leaks)
	}
}

func TestResumeStrictlyAfterBookmark(t *testing.T) {
	f := newFake(5, 6, 7, 8)
	got, err := collect(t, f, Resume{Bookmark: "bm:6", Initialized: true}, 2, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.flags != subscribeStartAfterBookmark|subscribeStrict {
		t.Fatalf("flags %#x: a stale bookmark must fail, not silently restart", f.flags)
	}
	if len(got) != 2 || got[0].RecordID != 7 || got[1].RecordID != 8 || got[1].Bookmark != "bm:8" {
		t.Fatalf("events %+v", got)
	}
	if !strings.HasPrefix(got[0].Line, "EventID=701") {
		t.Fatalf("FormatXML line contract changed: %q", got[0].Line)
	}
}

func TestEmptyBaselineStartsAtOldestRetained(t *testing.T) {
	f := newFake(1, 2)
	got, err := collect(t, f, Resume{Empty: true, Initialized: true}, 2, nil)
	if !errors.Is(err, context.Canceled) || f.flags != subscribeStartAtOldest {
		t.Fatalf("err=%v flags=%#x", err, f.flags)
	}
	if len(got) != 2 || got[0].RecordID != 1 {
		t.Fatalf("events written while the agent was down were not recovered: %+v", got)
	}
}

func TestUninitializedResumeIsRefused(t *testing.T) {
	if err := subscribeResume(context.Background(), lockedFake{newFake(1)}, "T", Resume{}, nil); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("got %v", err)
	}
}

func TestStaleOrInvalidBookmarkIsAGap(t *testing.T) {
	f := newFake(10, 11) // record 6 was cleared away
	if _, err := collect(t, f, Resume{Bookmark: "bm:6", Initialized: true}, 1, nil); !errors.Is(err, ErrBookmarkGap) {
		t.Fatalf("missing bookmarked event: %v", err)
	}
	f = newFake(1)
	if _, err := collect(t, f, Resume{Bookmark: "garbage", Initialized: true}, 1, nil); !errors.Is(err, ErrBookmarkGap) {
		t.Fatalf("invalid bookmark XML: %v", err)
	}
	f = newFake(1, 2)
	f.failNext = errQueryResultStale // cleared while subscribed
	if _, err := collect(t, f, Resume{Empty: true, Initialized: true}, 1, nil); !errors.Is(err, ErrBookmarkGap) {
		t.Fatalf("stale result set: %v", err)
	}
	f = newFake(1)
	f.failSub = errors.New("access denied")
	if _, err := collect(t, f, Resume{Empty: true, Initialized: true}, 1, nil); err == nil || errors.Is(err, ErrBookmarkGap) {
		t.Fatalf("a non-gap failure must not be reported as a gap: %v", err)
	}
}

func TestRenderAndFormatFailuresAreReportedNotSkipped(t *testing.T) {
	f := newFake(1, 2, 3)
	f.badRender[1] = true
	f.badXML[2] = true
	got, err := collect(t, f, Resume{Empty: true, Initialized: true}, 3, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got[0].Err == nil || got[0].Line != "" || got[0].Bookmark != "bm:1" {
		t.Fatalf("render failure: %+v", got[0])
	}
	if got[1].Err == nil || got[1].Line != "" || got[1].Bookmark != "bm:2" {
		t.Fatalf("format failure: %+v", got[1])
	}
	if got[2].Err != nil || got[2].Line == "" {
		t.Fatalf("good event: %+v", got[2])
	}
}

func TestAdmissionErrorStopsAndClosesTheRestOfTheBatch(t *testing.T) {
	f := newFake(1, 2, 3, 4)
	full := errors.New("journal full")
	var seen []uint64
	_, err := collect(t, f, Resume{Empty: true, Initialized: true}, 10, func(ev Event) error {
		seen = append(seen, ev.RecordID)
		if ev.RecordID == 2 {
			return full
		}
		return nil
	})
	if !errors.Is(err, full) {
		t.Fatalf("admission error not propagated: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("kept enumerating after a refused admission: %v", seen)
	}
	// collect already asserted that handles 3 and 4 were closed
}
