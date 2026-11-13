package appcontrol

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
}

// Controller keeps the WDAC policy in step with the rules and the mode.
type Controller struct {
	Dir  string // state and work files
	Run  Runner // nil: App Control is not available on this OS
	Push func(logType, line string)
	In   Inputs

	mu      sync.Mutex
	st      state
	health  Health
	wake    chan struct{}
	loaded  bool
	lastTry string // the plan key last attempted, so a failing plan is not retried every minute
	triedAt time.Time
}

const (
	reconcileEvery = time.Minute
	retryFailed    = 30 * time.Minute
	scriptTimeout  = 5 * time.Minute
)

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
	if ruleType != "hash" && ruleType != "known_malware" {
		return // path and dir rules are already in the policy
	}
	if !winAbs.MatchString(path) {
		return
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
	var rules [][2]string
	if c.In.Rules != nil {
		rules = c.In.Rules()
	}
	plan := NewPlan(mode, rules, c.st.Learned)
	key := ""
	if mode != ModeOff {
		key = plan.Key()
	}
	if key == c.st.Applied {
		return
	}
	if key == c.lastTry && time.Since(c.triedAt) < retryFailed {
		return
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
		c.health = Health{Mode: mode, Rules: plan.Rules(), Error: truncate(err.Error(), 300)}
		slog.Warn("appcontrol: policy not applied", "mode", mode, "err", err)
		c.emit("app_control_failed", c.health)
		return
	}
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
