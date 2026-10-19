//go:build windows

package winevent

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procEvtQuery = modwevtapi.NewProc("EvtQuery")

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
)

// Query reads events already in channel that match an XPath filter (e.g.
// "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"),
// newest first, and hands each rendered event XML to fn — at most limit events.
func Query(ctx context.Context, channel, xpath string, limit int, fn func(raw []byte) error) error {
	if xpath == "" {
		xpath = "*"
	}
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	q, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return err
	}
	rs, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if rs == 0 {
		return fmt.Errorf("EvtQuery(%s): %w", channel, callErr)
	}
	defer procEvtClose.Call(rs)

	handles := make([]uintptr, batchSize)
	buf := make([]uint16, 16*1024)
	seen := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var returned uint32
		ok, _, nextErr := procEvtNext.Call(rs, batchSize, uintptr(unsafe.Pointer(&handles[0])), 1000, 0,
			uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if errors.Is(nextErr, errNoMoreItems) {
				return nil
			}
			return fmt.Errorf("EvtNext(%s): %w", channel, nextErr)
		}
		var cbErr error
		for _, h := range handles[:returned] {
			if cbErr == nil && (limit <= 0 || seen < limit) {
				if raw, rerr := render(h, &buf); rerr == nil {
					seen++
					cbErr = fn([]byte(raw))
				}
			}
			procEvtClose.Call(h) // close every handle of the batch, even after stopping
		}
		if cbErr != nil {
			return cbErr
		}
		if limit > 0 && seen >= limit {
			return nil
		}
	}
}
