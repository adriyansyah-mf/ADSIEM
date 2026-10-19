package detect

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

const eventLogType = "local_detection"

type Blocker interface {
	Add(ruleKey, ip string, ttl time.Duration) error
	BlockedCount() int
}

type Options struct {
	Rules           []Rule
	Buffer          *buffer.Buffer
	Blocker         Blocker
	MaxBlocked      int
	MaxBlocksPerMin int
	Now             func() time.Time
}

type Detection struct {
	Rule       string    `json:"rule"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Group      string    `json:"group"`
	Count      int       `json:"count"`
	WindowSec  int       `json:"window_seconds"`
	Blocked    bool      `json:"blocked"`
	BlockedFor int       `json:"blocked_for_seconds"`
	BlockedErr string    `json:"block_error,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}

type Engine struct {
	mu      sync.Mutex
	rules   []Rule
	buf     *buffer.Buffer
	blocker Blocker
	now     func() time.Time

	hits       map[string][]time.Time
	cooldown   map[string]time.Time
	blockTimes []time.Time
	maxBlocked int
	maxPerMin  int
}

func New(opts Options) *Engine {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxBlocked := opts.MaxBlocked
	if maxBlocked <= 0 {
		maxBlocked = 5000
	}
	maxPerMin := opts.MaxBlocksPerMin
	if maxPerMin <= 0 {
		maxPerMin = 10
	}

	rules := make([]Rule, 0, len(opts.Rules))
	for _, r := range opts.Rules {
		if r.enabled {
			rules = append(rules, r)
		}
	}

	return &Engine{
		rules:      rules,
		buf:        opts.Buffer,
		blocker:    opts.Blocker,
		now:        now,
		hits:       make(map[string][]time.Time),
		cooldown:   make(map[string]time.Time),
		maxBlocked: maxBlocked,
		maxPerMin:  maxPerMin,
	}
}

func (e *Engine) EnabledRules() []string {
	out := make([]string, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.Key)
	}
	return out
}

// Observe feeds one decoded log line into every enabled rule. It is called
// from the sender loop, so exactly one goroutine observes each event.
func (e *Engine) Observe(logType, line string) []Detection {
	if len(e.rules) == 0 {
		return nil
	}

	now := e.now()
	var out []Detection

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.rules {
		group, ok := rule.matches(logType, line)
		if !ok {
			continue
		}

		key := rule.Key + "\x00" + group
		if until, cooling := e.cooldown[key]; cooling {
			if now.Before(until) {
				continue
			}
			delete(e.cooldown, key)
		}

		windowStart := now.Add(-rule.Window)
		hits := append(e.hits[key], now)
		pruned := hits[:0]
		for _, h := range hits {
			if h.After(windowStart) {
				pruned = append(pruned, h)
			}
		}
		e.hits[key] = pruned

		if len(pruned) < rule.Threshold {
			continue
		}

		det := Detection{
			Rule:       rule.Key,
			Title:      rule.Title,
			Severity:   rule.Severity,
			Group:      group,
			Count:      len(pruned),
			WindowSec:  int(rule.Window / time.Second),
			DetectedAt: now,
		}

		if rule.Action == actionBlock {
			e.applyBlock(&det, rule, group, now)
		}

		e.cooldown[key] = now.Add(rule.Cooldown)
		delete(e.hits, key)
		out = append(out, det)
	}

	return out
}

func (e *Engine) applyBlock(det *Detection, rule Rule, ip string, now time.Time) {
	if e.blocker == nil {
		det.BlockedErr = "firewall unavailable"
		return
	}

	cutoff := now.Add(-time.Minute)
	kept := e.blockTimes[:0]
	for _, t := range e.blockTimes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.blockTimes = kept

	if len(e.blockTimes) >= e.maxPerMin {
		det.BlockedErr = "rate limit: too many blocks per minute"
		slog.Warn("local detection suppressed a block", "rule", rule.Key, "reason", det.BlockedErr)
		return
	}
	if e.blocker.BlockedCount() >= e.maxBlocked {
		det.BlockedErr = "entry cap: too many blocked addresses"
		slog.Warn("local detection suppressed a block", "rule", rule.Key, "reason", det.BlockedErr)
		return
	}

	if err := e.blocker.Add(rule.Key, ip, rule.BlockFor); err != nil {
		det.BlockedErr = err.Error()
		slog.Warn("local detection block failed", "rule", rule.Key, "ip", ip, "err", err)
		return
	}

	det.Blocked = true
	det.BlockedFor = int(rule.BlockFor / time.Second)
	e.blockTimes = append(e.blockTimes, now)
}

// Emit publishes detections into the log buffer so they reach the SIEM once it
// is reachable again, and are visible locally immediately.
func (e *Engine) Emit(dets []Detection) {
	if e.buf == nil {
		return
	}
	for _, d := range dets {
		line, err := json.Marshal(d)
		if err != nil {
			continue
		}
		e.buf.Push(tailer.Encode(eventLogType, string(line)))
		slog.Info("local detection", "rule", d.Rule, "group", d.Group,
			"count", d.Count, "blocked", d.Blocked, "error", d.BlockedErr)
	}
}

func (e *Engine) Summary() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{
		"enabled_rules":      e.EnabledRules(),
		"tracked_groups":     len(e.hits),
		"blocks_last_min":    len(e.blockTimes),
		"max_blocks_per_min": e.maxPerMin,
		"max_blocked":        e.maxBlocked,
	}
}

func (d Detection) String() string {
	return fmt.Sprintf("%s group=%s count=%d blocked=%t", d.Rule, d.Group, d.Count, d.Blocked)
}
