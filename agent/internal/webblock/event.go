package webblock

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// LogType of block events (decoders/web_block.yaml).
const LogType = "web_block"

// Event is one blocked request that reached the local page server.
type Event struct {
	Domain, Scheme, Path, Source, Reason, Process string
	PID                                           int
	Count                                         int
}

// kv quotes a value. The worker's kv parser unescapes only \" and \\; any
// other backslash sequence stays as literal text, which is safe for the
// control characters escaped here.
func kv(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// truncRunes cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Line is the log line the decoder reads.
func (e Event) Line() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "event=web_block action=blocked domain=%s scheme=%s path=%s source=%s reason=%s",
		kv(e.Domain), e.Scheme, kv(e.Path), kv(e.Source), kv(e.Reason))
	if e.Process != "" {
		fmt.Fprintf(&sb, " process=%s", kv(e.Process))
	}
	if e.PID != 0 {
		fmt.Fprintf(&sb, " pid=%d", e.PID)
	}
	if e.Count > 1 {
		fmt.Fprintf(&sb, " count=%d", e.Count)
	}
	return sb.String()
}

type limitKey struct {
	domain string
	pid    int
}

type limitState struct {
	last       time.Time
	suppressed int
}

const (
	limitWindow  = time.Minute
	limitMaxKeys = 4096
)

// Limiter allows one event per (domain, pid) per minute and counts the hits
// it suppressed in between.
type Limiter struct {
	mu sync.Mutex
	m  map[limitKey]*limitState

	// Global cap: at most globalMax lines per rolling minute whatever the keys.
	sent       []time.Time
	dropped    int
	lastDropLg time.Time
}

const globalMax = 120

// Allow reports whether to emit now; suppressed is the number of hits held
// back since the previous emit (only meaningful when emit is true).
func (l *Limiter) Allow(domain string, pid int, now time.Time) (emit bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[limitKey]*limitState{}
	}
	k := limitKey{domain, pid}
	st := l.m[k]
	if st != nil && !now.Before(st.last) && now.Sub(st.last) < limitWindow {
		st.suppressed++
		return false, 0
	}
	if st == nil {
		if len(l.m) >= limitMaxKeys {
			for key, s := range l.m {
				if now.Sub(s.last) >= limitWindow {
					delete(l.m, key)
				}
			}
			if len(l.m) >= limitMaxKeys { // all fresh: drop the table rather than grow
				l.m = map[limitKey]*limitState{}
			}
		}
		st = &limitState{}
		l.m[k] = st
	}
	if !l.globalAllow(now) {
		st.suppressed++
		return false, 0
	}
	suppressed = st.suppressed
	st.suppressed = 0
	st.last = now
	return true, suppressed
}

// globalAllow enforces the rolling per-minute cap; drops are counted and
// logged at debug level at most once a minute.
func (l *Limiter) globalAllow(now time.Time) bool {
	keep := l.sent[:0]
	for _, t := range l.sent {
		if now.Sub(t) < limitWindow {
			keep = append(keep, t)
		}
	}
	l.sent = keep
	if len(l.sent) >= globalMax {
		l.dropped++
		if now.Sub(l.lastDropLg) >= limitWindow {
			slog.Debug("webblock: block events dropped over the rate cap", "dropped", l.dropped)
			l.dropped = 0
			l.lastDropLg = now
		}
		return false
	}
	l.sent = append(l.sent, now)
	return true
}
