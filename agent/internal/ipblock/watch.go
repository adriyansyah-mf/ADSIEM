package ipblock

import (
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/tailer"
)

// LogType of the lines Watcher emits (decoders/ioc_match.yaml).
const LogType = "ioc_match"

const (
	dedupeFor    = 10 * time.Minute // one report per (address, process) in this window
	maxPerMinute = 120              // a flood of hits never floods the server
)

// Matcher answers whether an address is in the list.
type Matcher struct {
	hosts map[netip.Addr]string // single addresses, to their CIDR
	nets  []netip.Prefix        // everything broader
	list  *List
}

// NewMatcher indexes l (capped at MaxEntries like the firewall set).
func NewMatcher(l *List) *Matcher {
	m := &Matcher{hosts: map[netip.Addr]string{}, list: l}
	for _, c := range l.CIDRs() {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if p.IsSingleIP() {
			m.hosts[p.Addr()] = c
		} else {
			m.nets = append(m.nets, p)
		}
	}
	return m
}

// Match returns the listed CIDR containing a, or "".
func (m *Matcher) Match(a netip.Addr) string {
	a = a.Unmap()
	if c, ok := m.hosts[a]; ok {
		return c
	}
	for _, p := range m.nets {
		if p.Contains(a) {
			return p.String()
		}
	}
	return ""
}

// Watcher reads the network telemetry lines as they are buffered (the
// buffer's observer) and pushes an ioc_match line for each connection to or
// from a listed address.
type Watcher struct {
	push    func(logType, line string)
	blocked func() bool // the firewall holds the list (mode block, enforcement up)
	m       atomic.Pointer[Matcher]

	mu     sync.Mutex
	seen   map[string]time.Time
	window time.Time
	count  int
	now    func() time.Time
}

// NewWatcher pushes ioc_match lines through push; blocked tells whether the
// connection was dropped (mode block and the firewall took the list).
func NewWatcher(push func(logType, line string), blocked func() bool) *Watcher {
	w := &Watcher{push: push, blocked: blocked, seen: map[string]time.Time{}, now: time.Now}
	w.m.Store(NewMatcher(Empty()))
	return w
}

// Update installs a new list (Store.OnChange).
func (w *Watcher) Update(l *List) { w.m.Store(NewMatcher(l)) }

// conn is the part of a telemetry line the watcher needs.
type conn struct {
	remote    []string // candidate remote addresses
	direction string
	pid       string
	image     string
}

// Observe takes one buffered entry (tailer-encoded).
func (w *Watcher) Observe(entry string) {
	m := w.m.Load()
	if m.list.Mode == "off" || (len(m.hosts) == 0 && len(m.nets) == 0) {
		return
	}
	logType, _, line := tailer.Decode(entry)
	c, ok := parse(logType, line)
	if !ok {
		return
	}
	for _, raw := range c.remote {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		cidr := m.Match(a)
		if cidr == "" {
			continue
		}
		w.report(logType, a.Unmap().String(), cidr, m.list, c)
		return
	}
}

func (w *Watcher) report(logType, ip, cidr string, l *List, c conn) {
	now := w.now()
	w.mu.Lock()
	key := ip + "|" + c.pid
	if t, ok := w.seen[key]; ok && now.Sub(t) < dedupeFor {
		w.mu.Unlock()
		return
	}
	if now.Sub(w.window) >= time.Minute {
		w.window, w.count = now, 0
		for k, t := range w.seen {
			if now.Sub(t) >= dedupeFor {
				delete(w.seen, k)
			}
		}
	}
	if w.count >= maxPerMinute {
		w.mu.Unlock()
		return
	}
	w.count++
	w.seen[key] = now
	w.mu.Unlock()

	entry := l.Entries[cidr]
	blocked := l.Mode == "block" && w.blocked != nil && w.blocked()
	line, _ := json.Marshal(map[string]any{
		"event":     "ip_ioc_match",
		"ip":        ip,
		"cidr":      cidr,
		"mode":      l.Mode,
		"blocked":   blocked,
		"direction": c.direction,
		"pid":       c.pid,
		"image":     c.image,
		"source":    entry.Source,
		"reason":    entry.Reason,
		"telemetry": logType,
		"ts":        now.UTC().Format(time.RFC3339Nano),
	})
	w.push(LogType, string(line))
}

// parse extracts the remote side of a connection line: Linux netwatch
// (eBPF and the ss fallback) and Windows ETW (Sysmon 3 lookalike).
func parse(logType, line string) (conn, bool) {
	switch logType {
	case "linux_network_connect", "linux_network_accept":
		f := fields(line)
		c := conn{direction: f["direction"], pid: f["tgid"], image: f["comm"]}
		if c.pid == "" {
			c.pid = f["pid"]
		}
		if logType == "linux_network_connect" {
			c.remote = []string{f["dst"]}
		} else {
			c.remote = []string{f["src"], f["dst"]}
		}
		return c, true
	case "windows_etw_network":
		f := fields(line)
		c := conn{pid: f["ProcessId"], image: f["Image"], direction: "inbound"}
		if f["Initiated"] == "true" {
			c.direction, c.remote = "outbound", []string{f["DestinationIp"]}
		} else {
			c.remote = []string{f["SourceIp"]}
		}
		return c, true
	case "linux_network_snapshot":
		return parseSS(line)
	}
	return conn{}, false
}

// parseSS reads an `ss -tunapH` line: netid state recv-q send-q local peer process.
func parseSS(line string) (conn, bool) {
	cols := strings.Fields(line)
	if len(cols) < 6 {
		return conn{}, false
	}
	c := conn{remote: []string{hostOf(cols[5])}, direction: "unknown"}
	if len(cols) > 6 {
		proc := strings.Join(cols[6:], " ")
		if i := strings.Index(proc, "pid="); i >= 0 {
			rest := proc[i+4:]
			if j := strings.IndexAny(rest, ",)"); j >= 0 {
				c.pid = rest[:j]
			}
		}
		if i := strings.Index(proc, `(("`); i >= 0 {
			rest := proc[i+3:]
			if j := strings.Index(rest, `"`); j >= 0 {
				c.image = rest[:j]
			}
		}
	}
	return c, true
}

// hostOf strips the port (and an IPv6 zone or brackets) from "addr:port".
func hostOf(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if i := strings.Index(s, "%"); i >= 0 {
		s = s[:i]
	}
	return s
}

// fields parses key=value and key="value" pairs like the server's kv decoder
// (inside quotes \" is a quote and \\ a backslash).
func fields(line string) map[string]string {
	out := make(map[string]string, 16)
	i, n := 0, len(line)
	for i < n {
		for i < n && line[i] == ' ' {
			i++
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= n || line[i] != '=' {
			continue
		}
		key := line[start:i]
		i++
		var val string
		if i < n && line[i] == '"' {
			i++
			var b strings.Builder
			for i < n && line[i] != '"' {
				if line[i] == '\\' && i+1 < n && (line[i+1] == '"' || line[i+1] == '\\') {
					i++
				}
				b.WriteByte(line[i])
				i++
			}
			i++
			val = b.String()
		} else {
			s := i
			for i < n && line[i] != ' ' {
				i++
			}
			val = line[s:i]
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}
