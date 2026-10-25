package winevent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// ErrBookmarkGap means the saved bookmark no longer names a retained event
// (the channel was cleared or rolled over): events after it may be lost.
var ErrBookmarkGap = errors.New("winevent: bookmarked event no longer retained")

// ErrNotInitialized means SubscribeResume was given no baseline.
var ErrNotInitialized = errors.New("winevent: resume point not initialized")

// Event is one channel event: its FormatXML line and the bookmark just past
// it. Err is set, and Line empty, when the event could not be rendered or
// formatted; Bookmark still moves past it, so the caller decides to record
// that and commit, or stop.
type Event struct {
	Line     string
	Bookmark string
	RecordID uint64
	Err      error
}

// Resume is where a subscription starts: strictly after Bookmark, or at the
// oldest retained event when the channel was empty at baseline (Empty).
type Resume struct {
	Bookmark    string
	Empty       bool
	Initialized bool
}

// Windows Event Log API values (winevt.h, winerror.h).
const (
	subscribeStartAtOldest      = 2
	subscribeStartAfterBookmark = 3
	subscribeStrict             = 0x10000

	errNotFound         = syscall.Errno(1168)  // ERROR_NOT_FOUND
	errQueryResultStale = syscall.Errno(15011) // ERROR_EVT_QUERY_RESULT_STALE
	errInvalidPosition  = syscall.Errno(15012) // ERROR_EVT_QUERY_RESULT_INVALID_POSITION
	resumeBatch         = 64
	resumeWaitInterval  = 250 * time.Millisecond
)

type handle uintptr

// subscription is an open EvtSubscribe result set with its signal event.
type subscription interface {
	// wait returns when events may be ready, after at most timeout.
	wait(timeout time.Duration) error
	// next returns up to max event handles; none when no more are ready.
	next(max int) ([]handle, error)
	close()
}

// nativeAPI is the part of wevtapi.dll the resume logic needs; tests fake it.
type nativeAPI interface {
	subscribe(channel string, bookmark handle, flags uint32) (subscription, error)
	renderXML(h handle) (string, error)
	createBookmark(xml string) (handle, error)
	updateBookmark(bookmark, event handle) error
	renderBookmark(bookmark handle) (string, error)
	// latest returns the newest retained event, ok=false when the channel is empty.
	latest(channel string) (h handle, ok bool, err error)
	close(h handle)
}

func isGap(err error) bool {
	return errors.Is(err, errNotFound) || errors.Is(err, errQueryResultStale) || errors.Is(err, errInvalidPosition)
}

// baseline bookmarks the newest retained event, or reports an empty channel,
// so a first subscription neither replays history nor misses events created
// between the baseline and the subscription.
func baseline(api nativeAPI, channel string) (Resume, error) {
	h, ok, err := api.latest(channel)
	if err != nil {
		return Resume{}, fmt.Errorf("query newest %s event: %w", channel, err)
	}
	if !ok {
		return Resume{Empty: true, Initialized: true}, nil
	}
	defer api.close(h)
	bm, err := api.createBookmark("")
	if err != nil {
		return Resume{}, fmt.Errorf("create bookmark: %w", err)
	}
	defer api.close(bm)
	if err := api.updateBookmark(bm, h); err != nil {
		return Resume{}, fmt.Errorf("update bookmark: %w", err)
	}
	xml, err := api.renderBookmark(bm)
	if err != nil {
		return Resume{}, fmt.Errorf("render bookmark: %w", err)
	}
	return Resume{Bookmark: xml, Initialized: true}, nil
}

// subscribeResume streams events after resume to emit until ctx ends, one
// call per EvtNext batch (oldest first; each event carries the bookmark just
// past it), so the caller can admit a batch in one group commit. An emit
// error stops it and is returned: the caller's committed bookmark is unchanged
// and it resubscribes from there. A failure moving the bookmark mid-batch
// emits the events before it, then returns. Every enumerated handle is closed.
func subscribeResume(ctx context.Context, api nativeAPI, channel string, resume Resume, emit func([]Event) error) error {
	var (
		bm    handle
		err   error
		flags uint32
		start handle
	)
	switch {
	case resume.Bookmark != "":
		if bm, err = api.createBookmark(resume.Bookmark); err != nil {
			return fmt.Errorf("%w: saved bookmark is invalid: %v", ErrBookmarkGap, err)
		}
		flags, start = subscribeStartAfterBookmark|subscribeStrict, bm
	case resume.Empty:
		if bm, err = api.createBookmark(""); err != nil {
			return fmt.Errorf("create bookmark: %w", err)
		}
		flags = subscribeStartAtOldest
	default:
		return ErrNotInitialized
	}
	defer api.close(bm)

	sub, err := api.subscribe(channel, start, flags)
	if err != nil {
		if isGap(err) {
			return fmt.Errorf("%w: %v", ErrBookmarkGap, err)
		}
		return fmt.Errorf("EvtSubscribe(%s): %w", channel, err)
	}
	defer sub.close()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := sub.wait(resumeWaitInterval); err != nil {
			return fmt.Errorf("wait for %s events: %w", channel, err)
		}
		for {
			hs, err := sub.next(resumeBatch)
			if err != nil {
				if isGap(err) {
					return fmt.Errorf("%w: %v", ErrBookmarkGap, err)
				}
				return fmt.Errorf("EvtNext(%s): %w", channel, err)
			}
			if len(hs) == 0 {
				break
			}
			evs := make([]Event, 0, len(hs))
			for i, h := range hs {
				ev, err := event(api, bm, h)
				api.close(h)
				if err != nil {
					for _, rest := range hs[i+1:] {
						api.close(rest)
					}
					if len(evs) > 0 {
						if emitErr := emit(evs); emitErr != nil {
							return emitErr
						}
					}
					return err
				}
				evs = append(evs, ev)
			}
			if err := emit(evs); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
}

// eachEvent adapts a per-event emit to batches: events in order, stopping at
// the first error.
func eachEvent(emit func(Event) error) func([]Event) error {
	return func(evs []Event) error {
		for _, ev := range evs {
			if err := emit(ev); err != nil {
				return err
			}
		}
		return nil
	}
}

// event renders h and moves bm past it while the handle is still valid.
func event(api nativeAPI, bm, h handle) (Event, error) {
	var ev Event
	raw, err := api.renderXML(h)
	if err != nil {
		ev.Err = fmt.Errorf("render event: %w", err)
	} else {
		ev.RecordID = recordID(raw)
		if ev.Line, err = FormatXML([]byte(raw)); err != nil {
			ev.Line, ev.Err = "", fmt.Errorf("format event: %w", err)
		}
	}
	if err := api.updateBookmark(bm, h); err != nil {
		return Event{}, fmt.Errorf("update bookmark: %w", err)
	}
	if ev.Bookmark, err = api.renderBookmark(bm); err != nil {
		return Event{}, fmt.Errorf("render bookmark: %w", err)
	}
	return ev, nil
}

var recordIDPattern = regexp.MustCompile(`<EventRecordID>(\d+)</EventRecordID>`)

func recordID(raw string) uint64 {
	m := recordIDPattern.FindStringSubmatch(raw)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseUint(m[1], 10, 64)
	return n
}
