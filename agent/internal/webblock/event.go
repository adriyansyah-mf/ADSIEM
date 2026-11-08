package webblock

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// LogType of block events (decoders/web_block.yaml).
const LogType = "web_block"

// Event is one blocked request that reached the local page server.
type Event struct {
	Domain, Scheme, Path, Source, Reason, Process string
	PID                                           int
	Count                                         int
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return `"` + s + `"`
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
}

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
	suppressed = st.suppressed
	st.suppressed = 0
	st.last = now
	return true, suppressed
}
