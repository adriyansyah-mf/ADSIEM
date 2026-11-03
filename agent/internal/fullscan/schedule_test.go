package fullscan

import (
	"testing"
	"time"
)

func TestParseSpec(t *testing.T) {
	for s, ok := range map[string]bool{"12:30": true, "daily 02:00": true, "sun 02:00": true, "MON 23:59": true,
		"": false, "25:00": false, "sun": false, "sunday 02:00": false, "12:3x": false, "mon tue 01:00": false} {
		if _, got := ParseSpec(s); got != ok {
			t.Errorf("ParseSpec(%q) = %v", s, got)
		}
	}
}

func TestDue(t *testing.T) {
	loc := time.UTC
	sunday := time.Date(2026, 11, 8, 0, 0, 0, 0, loc) // a Sunday
	at := func(d time.Time, h, m int) time.Time {
		return d.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
	}
	never := time.Time{}
	cases := []struct {
		spec     string
		now, run time.Time
		want     bool
	}{
		{"12:00", at(sunday, 11, 59), at(sunday, -11, 59), false},      // not yet (yesterday's ran)
		{"12:00", at(sunday, 12, 0), never, true},                      // on time
		{"12:00", at(sunday, 18, 0), never, true},                      // missed (host off at noon): later that day
		{"12:00", at(sunday, 18, 0), at(sunday, 12, 1), false},         // ran already
		{"12:00", at(sunday, 11, 0), at(sunday, -13, 0), true},         // yesterday's slot, not run, under a day ago
		{"sun 02:00", at(sunday, 3, 0), never, true},                   // weekly, on the day
		{"sun 02:00", at(sunday.AddDate(0, 0, 1), 3, 0), never, false}, // Monday: the Sunday slot is over a day old
		{"daily 02:00", at(sunday, 2, 30), at(sunday, -22, 0), true},
		{"", at(sunday, 12, 0), never, false},
	}
	for _, c := range cases {
		if got := Due(c.spec, c.now, c.run); got != c.want {
			t.Errorf("Due(%q, %s, last %s) = %v, want %v", c.spec, c.now.Format(time.RFC3339), c.run.Format(time.RFC3339), got, c.want)
		}
	}
}
