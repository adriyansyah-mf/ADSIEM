package appcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/authenticode"
)

// LogType of the lines the controller emits (decoders/app_control.yaml).
const LogType = "app_control"

// Runner runs a PowerShell script and returns its output (powershell.go).
type Runner func(ctx context.Context, script string) (string, error)

// Inputs is what the policy is built from, read at every reconcile.
type Inputs struct {
	Mode  func() string      // the group policy's app_control
	Rules func() [][2]string // block rules in force: (rule type, value)
}

// Health is the last outcome, for events and the dashboard.
type Health struct {
	Mode      string `json:"mode"`
	Rules     int    `json:"rules"`
	Method    string `json:"method,omitempty"` // citool, cim, reboot (removed, unloads at boot)
	AppliedAt string `json:"applied_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type state struct {
	Applied string   `json:"applied"` // Plan.Key of the policy in force ("" = none)
	Learned []string `json:"learned"`
	// Signers: per lower-case publisher, a file it signed that a signer
	// rule stopped (the sample ConfigCI builds the publisher rule from)
	Signers map[string]string `json:"signers,omitempty"`
}

// MaxSigners bounds the learned publisher samples.
const MaxSigners = 200

// Controller keeps the WDAC policy in step with the rules and the mode.
type Controller struct {
	Dir  string // state and work files
	Run  Runner // nil: App Control is not available on this OS
	Push func(logType, line string)
	In   Inputs

	// Supported reports why this Windows cannot build a policy (Home has no
	// ConfigCI module); nil func: assumed supported. Checked before any
	// script, so an unsupported host never runs PowerShell for it.
	Supported func() error

	mu      sync.Mutex
	st      state
	health  Health
	wake    chan struct{}
	loaded  bool
	lastTry string // the plan key last attempted, so a failing plan is not retried every minute
	triedAt time.Time
	fails   int // consecutive failures of lastTry: each one doubles the wait
	// fragTried: when a publisher fragment was last attempted (a failed
	// build is retried after retryFailed)
	fragTried map[string]time.Time
}

// fragmentTimeout bounds one publisher fragment build: New-CIPolicyRule
// -Level Publisher took from about a minute to over five on a GitHub runner.
const fragmentTimeout = 15 * time.Minute

// fragmentPath is where the publisher's deny fragment is kept (survives restarts).
func (c *Controller) fragmentPath(publisher string) string {
	sum := sha256.Sum256([]byte(publisher))
	return filepath.Join(c.Dir, "appcontrol", "publishers", hex.EncodeToString(sum[:8])+".xml")
}

// fragments returns the publisher fragments ready for the signer block
// rules, building at most one missing fragment per call (the slow part of a
// publisher rule, done once and kept). Until a publisher's fragment exists
// its programs are still stopped right after they start. c.mu held.
func (c *Controller) fragments(ctx context.Context, rules [][2]string) map[string]string {
	ready := map[string]string{}
	var missing []string
	for _, r := range rules {
		if r[0] != "signer" {
			continue
		}
		pub := strings.ToLower(strings.TrimSpace(r[1]))
		if _, learned := c.st.Signers[pub]; !learned || strings.Contains(pub, "microsoft") {
			continue
		}
		frag := c.fragmentPath(pub)
		if _, err := os.Stat(frag); err == nil {
			ready[pub] = frag
			continue
		}
		if t, ok := c.fragTried[pub]; ok && time.Since(t) < retryFailed {
			continue
		}
		missing = append(missing, pub)
	}
	if len(missing) == 0 {
		return ready
	}
	sort.Strings(missing)
	pub := missing[0]
	if c.fragTried == nil {
		c.fragTried = map[string]time.Time{}
	}
	c.fragTried[pub] = time.Now()
	fctx, cancel := context.WithTimeout(ctx, fragmentTimeout)
	defer cancel()
	start := time.Now()
	frag := c.fragmentPath(pub)
	if _, err := c.Run(fctx, FragmentScript(c.st.Signers[pub], frag)); err != nil {
		slog.Warn("appcontrol: publisher rule not built yet; its programs are still stopped at start",
			"publisher", pub, "err", err)
		return ready
	}
	if _, err := os.Stat(frag); err == nil {
		ready[pub] = frag
		slog.Info("appcontrol: publisher rule built", "publisher", pub, "took", time.Since(start).Round(time.Second))
	}
	return ready
}

const (
	reconcileEvery = time.Minute
	retryFailed    = 30 * time.Minute
	retryMax       = 24 * time.Hour
	scriptTimeout  = 5 * time.Minute
)

// retryAfter is the wait before a plan that failed n times in a row is tried
// again: 30 min, 1 h, 2 h ... up to a day. Each try runs PowerShell, and a
// host where it keeps failing must not raise an alert every half hour.
func retryAfter(n int) time.Duration {
	d := retryFailed
	for i := 1; i < n && d < retryMax; i++ {
		d *= 2
	}
	return min(d, retryMax)
}

func (c *Controller) statePath() string { return filepath.Join(c.Dir, "appcontrol.json") }

func (c *Controller) load() {
	if c.loaded {
		return
	}
	c.loaded = true
	if c.wake == nil {
		c.wake = make(chan struct{}, 1)
	}
	if data, err := os.ReadFile(c.statePath()); err == nil {
		_ = json.Unmarshal(data, &c.st)
	}
}

func (c *Controller) save() {
	data, _ := json.Marshal(c.st)
	if err := os.MkdirAll(c.Dir, 0o700); err == nil {
		tmp := c.statePath() + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, c.statePath())
		}
	}
}

// Learn records a file a hash rule stopped; App Control denies it by its
// Authenticode hash from the next reconcile on. Only Windows executables are
// learned (the path must be absolute) and at most MaxLearned, oldest first out.
func (c *Controller) Learn(ruleType, path, _ string) {
	if !winAbs.MatchString(path) {
		return
	}
	if ruleType == "signer" {
		c.learnSigner(path)
		return
	}
	if ruleType != "hash" && ruleType != "known_malware" {
		return // path and dir rules are already in the policy
	}
	c.mu.Lock()
	c.load()
	for _, f := range c.st.Learned {
		if strings.EqualFold(f, path) {
			c.mu.Unlock()
			return
		}
	}
	c.st.Learned = append(c.st.Learned, path)
	if len(c.st.Learned) > MaxLearned {
		c.st.Learned = c.st.Learned[len(c.st.Learned)-MaxLearned:]
	}
	c.save()
	wake := c.wake
	c.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

// learnSigner records a file a signer rule stopped as its publisher's
// sample: from the next reconcile on, App Control denies everything that
// publisher signed, before it runs. Read here, from the file itself, so the
// sample is keyed by the publisher it really carries.
func (c *Controller) learnSigner(path string) {
	sig, err := readSigner(path)
	if err != nil || sig == "" {
		return
	}
	key := strings.ToLower(strings.TrimSpace(sig))
	c.mu.Lock()
	c.load()
	if c.st.Signers == nil {
		c.st.Signers = map[string]string{}
	}
	if strings.EqualFold(c.st.Signers[key], path) {
		c.mu.Unlock()
		return
	}
	if _, known := c.st.Signers[key]; !known && len(c.st.Signers) >= MaxSigners {
		c.mu.Unlock()
		return
	}
	c.st.Signers[key] = path
	c.save()
	wake := c.wake
	c.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

// readSigner is replaced in tests.
var readSigner = func(path string) (string, error) {
	s, err := authenticode.ReadFile(path)
	return s.Publisher, err
}

// Health is the last outcome.
func (c *Controller) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

// Loop reconciles every minute and whenever a file is learned, until ctx ends.
func (c *Controller) Loop(ctx context.Context) {
	c.mu.Lock()
	c.load()
	wake := c.wake
	c.mu.Unlock()
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		c.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-wake:
		}
	}
}

// Reconcile applies the policy the inputs call for, if it differs from the
// one in force. A plan that failed is retried after retryFailed.
func (c *Controller) Reconcile(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	mode := ModeOff
	if c.In.Mode != nil {
		mode = c.In.Mode()
	}
	if mode != ModeAudit && mode != ModeEnforce {
		mode = ModeOff
	}
	if c.Run == nil {
		if mode != ModeOff && c.health.Error == "" {
			c.health = Health{Mode: mode, Error: "App Control is Windows only (Linux blocks before exec with BPF LSM)"}
		}
		return
	}
	if mode != ModeOff && c.Supported != nil {
		if err := c.Supported(); err != nil {
			if msg := err.Error(); c.health.Error != msg || c.health.Mode != mode {
				c.health = Health{Mode: mode, Error: msg}
				slog.Warn("appcontrol: not available on this host", "mode", mode, "err", err)
				c.emit("app_control_failed", c.health) // once per mode, not every minute
			}
			return
		}
	}
	var rules [][2]string
	if c.In.Rules != nil {
		rules = c.In.Rules()
	}
	var ready map[string]string
	if mode != ModeOff {
		ready = c.fragments(ctx, rules)
	}
	plan := NewPlan(mode, rules, c.st.Learned, ready)
	key := ""
	if mode != ModeOff {
		key = plan.Key()
	}
	if key == c.st.Applied {
		return
	}
	if key == c.lastTry && c.fails > 0 && time.Since(c.triedAt) < retryAfter(c.fails) {
		return
	}
	if key != c.lastTry {
		c.fails = 0 // a new plan is tried at once
	}
	c.lastTry, c.triedAt = key, time.Now()

	sctx, cancel := context.WithTimeout(ctx, scriptTimeout)
	defer cancel()
	var out string
	var err error
	if mode == ModeOff {
		out, err = c.Run(sctx, RemoveScript())
	} else {
		out, err = c.Run(sctx, ApplyScript(plan, filepath.Join(c.Dir, "appcontrol")))
	}
	method := lastLine(out)
	now := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		c.fails++
		c.health = Health{Mode: mode, Rules: plan.Rules(), Error: truncate(err.Error(), 300)}
		slog.Warn("appcontrol: policy not applied", "mode", mode, "err", err)
		c.emit("app_control_failed", c.health)
		return
	}
	c.fails = 0
	c.st.Applied = key
	c.save()
	c.health = Health{Mode: mode, Rules: plan.Rules(), Method: method, AppliedAt: now}
	event := "app_control_applied"
	if mode == ModeOff {
		event = "app_control_removed"
		if method == "none" {
			return // there was nothing to remove: not news
		}
	}
	slog.Info("appcontrol: policy updated", "mode", mode, "rules", plan.Rules(), "method", method)
	c.emit(event, c.health)
}

func (c *Controller) emit(event string, h Health) {
	if c.Push == nil {
		return
	}
	line, _ := json.Marshal(map[string]any{"event": event, "mode": h.Mode, "rules": h.Rules, "method": h.Method,
		"error": h.Error, "policy_id": PolicyID, "ts": time.Now().UTC().Format(time.RFC3339Nano)})
	c.Push(LogType, string(line))
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
