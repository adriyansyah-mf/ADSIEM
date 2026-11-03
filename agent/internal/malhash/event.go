package malhash

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/tlsh"
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
	// Match is "tlsh" for a file similar to a known one (a variant):
	// SimilarTo is that file's SHA-256 and Distance the TLSH distance.
	Match     string
	SimilarTo string
	Distance  int
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
	if e.Match != "" {
		fmt.Fprintf(&sb, " match=%s similar_to=%s distance=%d", e.Match, e.SimilarTo, e.Distance)
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
	// Excluded, when set, leaves out files the group policy excludes
	// (malware scope).
	Excluded func(path, sha string) bool

	mu   sync.Mutex
	last map[string]time.Time
}

// Check is the scanner's OnHash hook; true when it reported the file.
func (f *FileChecker) Check(path, sha string, size int64, trigger string) bool {
	set := f.Store.Current()
	if !set.Active() {
		return false
	}
	label, ok := set.Lookup(sha)
	if !ok || (f.Excluded != nil && f.Excluded(path, sha)) {
		return false
	}
	if !f.first(path + "|" + sha) {
		return false
	}
	e := Event{Action: "detected", Trigger: "file", Label: label, SHA256: sha, Path: path, Engine: engineOf(trigger),
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
	return true
}

// engineOf: the scanner's trigger names the engine in the line
// (on_access, or the scan that found it: quick_scan, full_scan, custom_scan).
func engineOf(trigger string) string {
	if trigger == "" {
		return "on_access"
	}
	return trigger
}

// VariantDistance: a file at most this TLSH distance from a known-malware
// file is reported as a variant of it. 30 is the conservative end of TLSH's
// published range (low false positives on executables).
const VariantDistance = 30

// variantMinSize: smaller files have too little content for TLSH to mean much.
const variantMinSize = 512

// CheckData is the scanner's OnData hook: a file whose SHA-256 is not known
// but whose TLSH is close to a known-malware file's is reported as a
// variant (detected only, never quarantined: similarity is not identity).
func (f *FileChecker) CheckData(path, sha string, data []byte, trigger string) bool {
	set := f.Store.Current()
	if !set.Active() || set.SimilarCount() == 0 || len(data) < variantMinSize {
		return false
	}
	if _, known := set.Lookup(sha); known {
		return false // Check reports it
	}
	h, err := tlsh.Sum(data)
	if err != nil {
		return false
	}
	label, similar, dist, ok := set.Similar(h, VariantDistance)
	if !ok || (f.Excluded != nil && f.Excluded(path, sha)) || !f.first(path+"|"+sha) {
		return false
	}
	e := Event{Action: "detected", Trigger: "file", Label: label, SHA256: sha, Path: path, Engine: engineOf(trigger),
		Size: int64(len(data)), Match: "tlsh", SimilarTo: similar, Distance: dist}
	slog.Warn("malhash: variant of known malware", "path", path, "label", label, "similar_to", similar, "distance", dist)
	f.Push(LogType, e.Line())
	return true
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
