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

// ELF model thresholds for a file in a staging directory (stagingDirs). The
// model's own thresholds sit where 1% / 0.1% of all benign ELF files score
// higher, but packaged software does not live in /tmp: a dropped miner there
// (otakunesia, 2026-11-11: /var/tmp/.7625e6d2e, model 0.98) ran for two days
// as "clean". Of 8,542 ELF files on a Kali host (security tools included) 6
// scored 0.95 or more, none of them in a staging directory; a go test binary
// in /tmp scored 0.82.
const (
	ELFStagingMalicious  = 0.95
	ELFStagingSuspicious = 0.90
)

// stagingDirs are where droppers write payloads: world-writable temp
// directories. systemd PrivateTmp directories are below them on the host
// (/var/tmp/systemd-private-.../tmp).
var stagingDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

func inStaging(path string) bool {
	for _, d := range stagingDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// Verdict is the score of one file.
type Verdict struct {
	Kind      string // pe or elf
	Engine    string // ember2024_lgbm / ember_lgbm (PE), ember2024_elf_lgbm or elf_heuristic (ELF)
	Level     string // malicious, suspicious or clean
	Score     float64
	Threshold float64 // the one Level crossed (malicious or suspicious)
	Reasons   []string
}

var levelRank = map[string]int{"clean": 0, "suspicious": 1, "malicious": 2}

func byThresholds(m *mlscore.Model, score float64) (level string, threshold float64) {
	// the thresholds are where 0.1% / 1% of the benign test files score
	// higher (ml/v3/train.py)
	switch {
	case score > m.Thresholds.FPR01:
		return "malicious", m.Thresholds.FPR01
	case score > m.Thresholds.FPR1:
		return "suspicious", m.Thresholds.FPR1
	}
	return "clean", 0
}

// Classify scores data with the PE model (files starting "MZ") or, for ELF
// files, the ELF model and the heuristics (the higher level wins; the
// heuristic reasons are kept). ok is false for anything else, or a PE a
// format-1 model cannot read. elf may be nil.
func Classify(m, elf *mlscore.Model, data []byte) (v Verdict, ok bool) {
	return ClassifyAt(m, elf, data, "")
}

// ClassifyAt is Classify for a file at path: an ELF file in a staging
// directory is held to the stricter ELFStaging thresholds of the ELF model.
func ClassifyAt(m, elf *mlscore.Model, data []byte, path string) (v Verdict, ok bool) {
	// malware ships malformed headers on purpose: a parser panic must not
	// take the agent down
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("mlscan: file not scored", "panic", r)
			v, ok = Verdict{}, false
		}
	}()
	if m != nil && len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		score, scored := m.ScoreFile(data)
		if !scored {
			return Verdict{}, false
		}
		v := Verdict{Kind: "pe", Engine: "ember_lgbm", Score: score}
		if m.Format == 2 {
			v.Engine = "ember2024_lgbm"
		}
		v.Level, v.Threshold = byThresholds(m, score)
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
	if elf != nil {
		if s, scored := elf.ScoreFile(data); scored {
			if level, th := byThresholds(elf, s); levelRank[level] >= levelRank[v.Level] {
				v.Engine, v.Score, v.Level, v.Threshold = "ember2024_elf_lgbm", s, level, th
			}
			if inStaging(path) {
				level, th := "clean", 0.0
				switch {
				case s >= ELFStagingMalicious:
					level, th = "malicious", ELFStagingMalicious
				case s >= ELFStagingSuspicious:
					level, th = "suspicious", ELFStagingSuspicious
				}
				if levelRank[level] > levelRank[v.Level] {
					v.Engine, v.Score, v.Level, v.Threshold = "ember2024_elf_lgbm", s, level, th
					v.Reasons = append(v.Reasons, "ELF in a temp directory")
				}
			}
		}
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
	// Trigger: on_access, or the scan that found it (quick_scan, full_scan,
	// custom_scan).
	Trigger string
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
	if e.Trigger != "" {
		fmt.Fprintf(&sb, " trigger=%s", e.Trigger)
	}
	if e.Error != "" {
		fmt.Fprintf(&sb, " error=%s", kv(e.Error))
	}
	return sb.String()
}

// Checker is the on-access scanner's OnData hook.
type Checker struct {
	Model      *mlscore.Model // PE
	ELF        *mlscore.Model // nil: the heuristics alone
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
// Check is the scanner's OnData hook; true when it reported the file.
func (c *Checker) Check(path, sha string, data []byte, trigger string) bool {
	mode := ModeDetect
	if c.Mode != nil {
		if m := c.Mode(path, sha); m != "" {
			mode = m
		}
	}
	if mode == ModeOff || (c.Known != nil && c.Known(sha)) {
		return false
	}
	v, ok := ClassifyAt(c.Model, c.ELF, data, path)
	if !ok || v.Level == "clean" || !c.first(path+"|"+sha) {
		return false
	}
	e := Event{Verdict: v, Action: "detected", SHA256: sha, Path: path, Size: int64(len(data)), Trigger: trigger}
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
	return true
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
