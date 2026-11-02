package malhash

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// LogType of known-malware lines (decoders/known_malware.yaml).
const LogType = "known_malware"

// Event is one known-malware hash seen on the host.
type Event struct {
	// Action: detected, blocked (exec refused), terminated (killed right
	// after it started), quarantined (file locked), or with Error what failed.
	Action  string
	Trigger string // exec or file
	Label   string
	SHA256  string
	Path    string
	Parent  string
	Engine  string // fanotify, etw, on_access
	PID     uint32
	PPID    uint32
	UID     uint32
	Size    int64
	Error   string
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// Line is the log line the decoder reads.
func (e Event) Line() string {
	label := e.Label
	if label == "" {
		label = "unknown"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "event=known_malware action=%s trigger=%s label=%s sha256=%s path=%s engine=%s",
		e.Action, e.Trigger, kv(label), e.SHA256, kv(e.Path), e.Engine)
	if e.Parent != "" {
		fmt.Fprintf(&sb, " parent=%s", kv(e.Parent))
	}
	if e.PID != 0 {
		fmt.Fprintf(&sb, " pid=%d ppid=%d uid=%d", e.PID, e.PPID, e.UID)
	}
	if e.Size > 0 {
		fmt.Fprintf(&sb, " size=%d", e.Size)
	}
	if e.Error != "" {
		fmt.Fprintf(&sb, " error=%s", kv(e.Error))
	}
	return sb.String()
}

// FileChecker checks files the on-access scanner hashed (OnHash): a known
// hash is reported and, when the server says block, quarantined.
type FileChecker struct {
	Store      *Store
	Push       func(logType, line string)
	Quarantine func(path string) error

	mu   sync.Mutex
	last map[string]time.Time
}

// Check is the scanner's OnHash hook.
func (f *FileChecker) Check(path, sha string, size int64) {
	set := f.Store.Current()
	if !set.Active() {
		return
	}
	label, ok := set.Lookup(sha)
	if !ok {
		return
	}
	if !f.first(path + "|" + sha) {
		return
	}
	e := Event{Action: "detected", Trigger: "file", Label: label, SHA256: sha, Path: path, Engine: "on_access",
		Size: size}
	if set.Block() && f.Quarantine != nil {
		if err := f.Quarantine(path); err != nil {
			e.Error = err.Error()
			slog.Warn("malhash: known malware not quarantined", "path", path, "err", err)
		} else {
			e.Action = "quarantined"
		}
	}
	slog.Warn("malhash: known malware", "path", path, "label", label, "action", e.Action)
	f.Push(LogType, e.Line())
}

// first: the same file and content is reported once a minute at most.
func (f *FileChecker) first(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.last == nil || len(f.last) > 10000 {
		f.last = map[string]time.Time{}
	}
	if t, ok := f.last[key]; ok && now.Sub(t) < time.Minute {
		return false
	}
	f.last[key] = now
	return true
}
