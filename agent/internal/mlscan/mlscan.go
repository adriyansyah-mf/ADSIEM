// Package mlscan is the static machine-learning check of files the on-access
// scanner reads (yarascan OnData): Windows PE files get the EMBER-trained
// model's score (internal/mlscore), ELF files the heuristic score. A file
// over the malicious threshold is reported and, when the group policy says
// block, quarantined; one over the suspicious threshold is only reported.
// It runs the same on Linux and Windows: either kind of file can land on
// either system (a web upload, a share, a Downloads folder).
package mlscan

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/mlscore"
)

// LogType of the lines (decoders/ml_detection.yaml).
const LogType = "ml_detection"

// Modes from the group policy (ml_action).
const (
	ModeOff    = "off"
	ModeDetect = "detect"
	ModeBlock  = "block"
)

// ELF thresholds of the heuristic score (mlscore.ScoreELF): malicious takes
// at least two strong traits (a mining pool URL and the miner's name, or
// UPX packing with no section headers and packed content).
const (
	ELFMalicious  = 0.7
	ELFSuspicious = 0.45
)

// Verdict is the score of one file.
type Verdict struct {
	Kind      string // pe or elf
	Engine    string // ember_lgbm or elf_heuristic
	Level     string // malicious, suspicious or clean
	Score     float64
	Threshold float64 // the one Level crossed (malicious or suspicious)
	Reasons   []string
}

// Classify scores data; ok is false when it is neither PE nor ELF (or the
// PE headers cannot be read).
func Classify(m *mlscore.Model, data []byte) (v Verdict, ok bool) {
	// malware ships malformed headers on purpose: a parser panic must not
	// take the agent down
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("mlscan: file not scored", "panic", r)
			v, ok = Verdict{}, false
		}
	}()
	if m != nil && mlscore.IsPE(data) {
		raw, err := mlscore.ExtractPE(data)
		if err != nil {
			return Verdict{}, false
		}
		v := Verdict{Kind: "pe", Engine: "ember_lgbm", Score: m.Score(mlscore.Vector(raw))}
		// the thresholds are where 0.1% / 1% of EMBER's benign test files
		// score higher (ml/train.py)
		switch {
		case v.Score > m.Thresholds.FPR01:
			v.Level, v.Threshold = "malicious", m.Thresholds.FPR01
		case v.Score > m.Thresholds.FPR1:
			v.Level, v.Threshold = "suspicious", m.Thresholds.FPR1
		default:
			v.Level = "clean"
		}
		return v, true
	}
	score, reasons, ok := mlscore.ScoreELF(data)
	if !ok {
		return Verdict{}, false
	}
	v = Verdict{Kind: "elf", Engine: "elf_heuristic", Score: score, Reasons: reasons}
	switch {
	case score >= ELFMalicious:
		v.Level, v.Threshold = "malicious", ELFMalicious
	case score >= ELFSuspicious:
		v.Level, v.Threshold = "suspicious", ELFSuspicious
	default:
		v.Level = "clean"
	}
	return v, true
}

// Event is one file over a threshold.
type Event struct {
	Verdict
	Action string // detected or quarantined
	SHA256 string
	Path   string
	Size   int64
	Error  string
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// Line is the log line the decoder reads.
func (e Event) Line() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "event=ml_detection action=%s level=%s kind=%s engine=%s score=%.4f threshold=%.4f sha256=%s path=%s size=%d",
		e.Action, e.Level, e.Kind, e.Engine, e.Score, e.Threshold, e.SHA256, kv(e.Path), e.Size)
	if len(e.Reasons) > 0 {
		fmt.Fprintf(&sb, " reasons=%s", kv(strings.Join(e.Reasons, "; ")))
	}
	if e.Error != "" {
		fmt.Fprintf(&sb, " error=%s", kv(e.Error))
	}
	return sb.String()
}

// Checker is the on-access scanner's OnData hook.
type Checker struct {
	Model      *mlscore.Model
	Push       func(logType, line string)
	Quarantine func(path string) error
	// Mode, when set, is the policy's ml_action for the file (off when an
	// exclusion with the ml scope matches); unset or empty means detect.
	Mode func(path, sha string) string
	// Known, when set and true, leaves out files the known-malware hash
	// database already reports (and blocks).
	Known func(sha string) bool

	mu   sync.Mutex
	last map[string]time.Time
}

// Check scores one file the scanner read.
func (c *Checker) Check(path, sha string, data []byte) {
	mode := ModeDetect
	if c.Mode != nil {
		if m := c.Mode(path, sha); m != "" {
			mode = m
		}
	}
	if mode == ModeOff || (c.Known != nil && c.Known(sha)) {
		return
	}
	v, ok := Classify(c.Model, data)
	if !ok || v.Level == "clean" || !c.first(path+"|"+sha) {
		return
	}
	e := Event{Verdict: v, Action: "detected", SHA256: sha, Path: path, Size: int64(len(data))}
	if mode == ModeBlock && v.Level == "malicious" && c.Quarantine != nil {
		if err := c.Quarantine(path); err != nil {
			e.Error = err.Error()
			slog.Warn("mlscan: not quarantined", "path", path, "err", err)
		} else {
			e.Action = "quarantined"
		}
	}
	slog.Warn("mlscan: "+v.Level+" file", "path", path, "kind", v.Kind, "score", v.Score, "action", e.Action)
	c.Push(LogType, e.Line())
}

// first: the same file and content is reported once an hour at most (the
// scanner already skips unchanged files; this covers its cache resets).
func (c *Checker) first(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.last == nil || len(c.last) > 10000 {
		c.last = map[string]time.Time{}
	}
	if t, ok := c.last[key]; ok && now.Sub(t) < time.Hour {
		return false
	}
	c.last[key] = now
	return true
}
