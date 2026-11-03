package fullscan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Schedules from the group policy: quick_scan_time "HH:MM" (every day) and
// full_scan_schedule "<day> HH:MM" (day: mon..sun or daily). "" is off.
// Times are the host's local time.

var weekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

// Spec is a parsed schedule.
type Spec struct {
	Daily        bool
	Day          time.Weekday
	Hour, Minute int
}

// ParseSpec reads "HH:MM", "daily HH:MM" or "<day> HH:MM".
func ParseSpec(s string) (Spec, bool) {
	f := strings.Fields(strings.ToLower(strings.TrimSpace(s)))
	sp := Spec{Daily: true}
	switch len(f) {
	case 1:
	case 2:
		if f[0] != "daily" {
			d, ok := weekdays[f[0]]
			if !ok {
				return Spec{}, false
			}
			sp.Daily, sp.Day = false, d
		}
		f = f[1:]
	default:
		return Spec{}, false
	}
	hm := strings.Split(f[0], ":")
	if len(hm) != 2 {
		return Spec{}, false
	}
	h, err1 := strconv.Atoi(hm[0])
	m, err2 := strconv.Atoi(hm[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return Spec{}, false
	}
	sp.Hour, sp.Minute = h, m
	return sp, true
}

// lastSlot is the most recent time at or before now the spec names.
func (sp Spec) lastSlot(now time.Time) time.Time {
	t := time.Date(now.Year(), now.Month(), now.Day(), sp.Hour, sp.Minute, 0, 0, now.Location())
	if t.After(now) {
		t = t.AddDate(0, 0, -1)
	}
	if !sp.Daily {
		for t.Weekday() != sp.Day {
			t = t.AddDate(0, 0, -1)
		}
	}
	return t
}

// Due reports whether a scan should start now: its last slot is not over
// a day old (a missed slot is caught up the same day, not days later) and
// no scan ran since.
func Due(spec string, now, lastRun time.Time) bool {
	sp, ok := ParseSpec(spec)
	if !ok {
		return false
	}
	slot := sp.lastSlot(now)
	return now.Sub(slot) < 24*time.Hour && lastRun.Before(slot)
}

// scheduleState is saved in the state directory.
type scheduleState struct {
	Quick time.Time `json:"quick"`
	Full  time.Time `json:"full"`
}

func loadState(path string) scheduleState {
	var st scheduleState
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func saveState(path string, st scheduleState) {
	b, _ := json.Marshal(st)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		slog.Warn("file scan: schedule state not saved", "path", path, "err", err)
	}
}

// Schedule starts the policy's scans. specs returns the quick and full
// schedules in force; start runs one scan (blocking) and is not called
// while a scan runs. The last run of each kind is kept in stateFile.
func Schedule(ctx context.Context, stateFile string, specs func() (quick, full string), start func(kind string)) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			quick, full := specs()
			st := loadState(stateFile)
			if st.Quick.IsZero() || st.Full.IsZero() {
				// first start: wait for the next slot, do not scan at once
				if st.Quick.IsZero() {
					st.Quick = now
				}
				if st.Full.IsZero() {
					st.Full = now
				}
				saveState(stateFile, st)
				continue
			}
			// a full scan covers the quick folders too
			switch {
			case Due(full, now, st.Full) && !Running():
				st.Full, st.Quick = now, now
				saveState(stateFile, st)
				start(KindFull)
			case Due(quick, now, st.Quick) && !Running():
				st.Quick = now
				saveState(stateFile, st)
				start(KindQuick)
			}
		}
	}
}

// ValidSpec reports whether s is "" or a schedule ParseSpec reads (the
// server checks the same format).
func ValidSpec(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if _, ok := ParseSpec(s); !ok {
		return fmt.Errorf("schedule %q: want HH:MM, daily HH:MM or <mon..sun> HH:MM", s)
	}
	return nil
}
