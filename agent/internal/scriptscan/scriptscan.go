// Package scriptscan scans script content before or as it runs, with the
// agent's YARA rules: on Windows what AMSI saw (PowerShell, VBScript,
// JScript, Office VBA, .NET; deobfuscated, from the AMSI ETW provider),
// on Linux the code given to an interpreter (-c / -e) or the script file it
// was started with. A match is a script_scan line; with the group policy's
// script_scan block, the process is stopped when the rule is high or critical.
package scriptscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/siem-platform/agent/internal/yara"
	"github.com/siem-platform/agent/internal/yarascan"
)

// LogType of script_scan lines (decoders/script_scan.yaml).
const LogType = "script_scan"

const (
	queueSize   = 256
	repeatEvery = 10 * time.Minute
	maxScript   = 1 << 20
	excerptLen  = 160
)

// Script is one piece of code about to run (or running).
type Script struct {
	PID     uint32
	Image   string // the host process (powershell.exe, /usr/bin/bash)
	App     string // AMSI app name, or the interpreter
	Name    string // script file or AMSI content name, "" for inline code
	Content []byte // UTF-8 (AMSI's UTF-16 is converted by the caller)
}

// Scanner queues scripts and scans them on its own goroutine.
type Scanner struct {
	Yara *yarascan.Scanner
	Push func(logType, line string)
	// Action is the group policy's script_scan: off, detect or block.
	Action func() string
	// Excluded leaves out what the policy excludes (script scope).
	Excluded func(image, name, sha string) bool
	// Kill stops a process (block mode); nil where there is none.
	Kill func(pid uint32) error
	Self uint32

	queue chan func() (Script, bool)
	mu    sync.Mutex
	seen  map[string]time.Time
	once  sync.Once
}

func (s *Scanner) init() {
	s.once.Do(func() {
		s.queue = make(chan func() (Script, bool), queueSize)
		s.seen = map[string]time.Time{}
	})
}

// Offer queues a script; a full queue drops it (never blocks the sensor).
func (s *Scanner) Offer(sc Script) {
	if sc.PID == s.Self || len(sc.Content) == 0 {
		return
	}
	s.enqueue(func() (Script, bool) { return sc, true })
}

// OfferExec queues a program start: when it is an interpreter, its script
// is read and scanned on the scanner's goroutine (not the sensor's).
func (s *Scanner) OfferExec(pid uint32, image string, args []string) {
	if pid == s.Self {
		return
	}
	if _, _, ok := interpreter(image); !ok {
		return
	}
	s.enqueue(func() (Script, bool) { return FromExec(pid, image, args) })
}

func (s *Scanner) enqueue(job func() (Script, bool)) {
	s.init()
	if s.Action != nil && s.Action() == "off" {
		return
	}
	select {
	case s.queue <- job:
	default:
	}
}

// Run scans queued scripts until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	s.init()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-s.queue:
			if sc, ok := job(); ok && len(sc.Content) > 0 {
				s.scan(ctx, sc)
			}
		}
	}
}

func (s *Scanner) first(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if t, ok := s.seen[key]; ok && now.Sub(t) < repeatEvery {
		return false
	}
	if len(s.seen) > 20000 {
		s.seen = map[string]time.Time{}
	}
	s.seen[key] = now
	return true
}

func (s *Scanner) scan(ctx context.Context, sc Script) {
	s.init()
	if len(sc.Content) > maxScript {
		sc.Content = sc.Content[:maxScript]
	}
	sum := sha256.Sum256(sc.Content)
	sha := hex.EncodeToString(sum[:])
	if !s.first(sha) {
		return // PowerShell scans the same block again and again
	}
	if s.Excluded != nil && s.Excluded(sc.Image, sc.Name, sha) {
		return
	}
	matches, err := s.Yara.ScanBytes(ctx, sc.Content)
	if err != nil || len(matches) == 0 {
		return
	}
	severity, names := worst(matches), make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, s.Yara.RuleName(m.Namespace)+"/"+m.Rule)
	}
	action := "detected"
	errText := ""
	if s.Action != nil && s.Action() == "block" && (severity == "critical" || severity == "high") && sc.PID > 4 {
		switch {
		case s.Kill == nil:
			errText = "stopping is not supported here"
		default:
			if err := s.Kill(sc.PID); err != nil {
				errText = err.Error()
			} else {
				action = "terminated"
			}
		}
	}
	slog.Warn("scriptscan: malicious script", "app", sc.App, "pid", sc.PID, "rules", names, "action", action)
	s.Push(LogType, Line(sc, sha, action, severity, names, excerpt(sc.Content, matches), errText))
}

var rank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

func worst(ms []yara.RuleMatch) string {
	best := "low"
	for _, m := range ms {
		if s := yarascan.Severity(m.Meta); rank[s] > rank[best] {
			best = s
		}
	}
	return best
}

// excerpt is up to excerptLen characters around the first match: enough to
// see what fired, not the whole script (it may hold secrets).
func excerpt(content []byte, ms []yara.RuleMatch) string {
	off := int64(0)
	for _, m := range ms {
		if len(m.Strings) > 0 {
			off = m.Strings[0].Offset
			break
		}
	}
	start := int(off) - excerptLen/4
	if start < 0 {
		start = 0
	}
	end := start + excerptLen
	if end > len(content) {
		end = len(content)
	}
	if start > end {
		start = end
	}
	for start < end && !utf8.RuneStart(content[start]) {
		start++
	}
	out := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(string(content[start:end]), ""))
	return out
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// Line is what decoders/script_scan.yaml reads.
func Line(sc Script, sha, action, severity string, rules []string, excerpt, errText string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "event=script_scan action=%s severity=%s app=%s image=%s pid=%d sha256=%s rules=%s excerpt=%s",
		action, severity, kv(sc.App), kv(sc.Image), sc.PID, sha, kv(strings.Join(rules, ",")), kv(excerpt))
	if sc.Name != "" {
		fmt.Fprintf(&sb, " name=%s", kv(sc.Name))
	}
	if errText != "" {
		fmt.Fprintf(&sb, " error=%s", kv(errText))
	}
	return sb.String()
}

// ─── Linux: what an interpreter was started with ─────────────────────

// interpreters and the flag that takes inline code.
var interpreters = map[string]string{
	"sh": "-c", "bash": "-c", "dash": "-c", "zsh": "-c", "ksh": "-c", "ash": "-c", "busybox": "-c",
	"python": "-c", "python2": "-c", "python3": "-c", "perl": "-e", "ruby": "-e", "php": "-r", "node": "-e",
	"pwsh": "-c", "lua": "-e",
}

func interpreter(image string) (name, flag string, ok bool) {
	b := filepath.Base(image)
	if f, ok := interpreters[b]; ok {
		return b, f, true
	}
	// python3.11, php8.2, perl5.36
	for _, prefix := range []string{"python3", "python2", "php", "perl"} {
		if strings.HasPrefix(b, prefix) {
			return b, interpreters[prefix], true
		}
	}
	return "", "", false
}

// FromExec is the script an interpreter was started with: its inline code,
// or the script file (read here, at most maxScript bytes). ok is false for
// any other program, or an interpreter reading its code from stdin.
func FromExec(pid uint32, image string, args []string) (Script, bool) {
	name, flag, ok := interpreter(image)
	if !ok || len(args) < 2 {
		return Script{}, false
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == flag || (flag == "-c" && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.HasSuffix(a, "c") && len(a) <= 4) {
			if i+1 < len(args) {
				return Script{PID: pid, Image: image, App: name, Content: []byte(strings.Join(args[i+1:], " "))}, true
			}
			return Script{}, false
		}
		if strings.HasPrefix(a, "-") {
			continue // an option (-u, -x, -W ignore ...)
		}
		path := a
		if !filepath.IsAbs(path) {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
				path = filepath.Join(cwd, path)
			}
		}
		data, err := readHead(path)
		if err != nil {
			return Script{}, false
		}
		return Script{PID: pid, Image: image, App: name, Name: path, Content: data}, true
	}
	return Script{}, false
}

func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	buf := make([]byte, maxScript)
	n, _ := f.Read(buf)
	return buf[:n], nil
}
