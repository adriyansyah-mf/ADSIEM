package firewall

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

const eventLogType = "firewall_gate"

type Options struct {
	Enabled      bool
	Backend      string
	DryRun       bool
	ProtectedIPs []string
	StatePath    string
	ServerURL    string
	Buffer       *buffer.Buffer
}

type Engine struct {
	mu       sync.Mutex
	backend  Backend
	guard    *Guard
	buf      *buffer.Buffer
	state    string
	dryRun   bool
	enabled  bool
	applied  map[string]Rule
	degraded string
}

func New(opts Options) *Engine {
	if v, ok := lookupEnv("SIEM_FW_DRY_RUN"); ok && isTruthy(v) {
		opts.DryRun = true
	}
	if v, ok := lookupEnv("SIEM_FW_BACKEND"); ok && v != "" {
		opts.Backend = v
	}
	if v, ok := lookupEnv("SIEM_FW_DISABLED"); ok && isTruthy(v) {
		opts.Enabled = false
	}

	e := &Engine{
		buf:     opts.Buffer,
		state:   opts.StatePath,
		dryRun:  opts.DryRun,
		enabled: opts.Enabled,
		applied: make(map[string]Rule),
	}
	e.guard = NewGuard(opts.ServerURL, opts.ProtectedIPs)

	switch {
	case !opts.Enabled:
		e.backend = NewNoop(opts.DryRun)
		e.degraded = "disabled in config"
	case opts.DryRun:
		e.backend = NewNoop(true)
		e.degraded = "dry-run"
		slog.Info("firewall gate in dry-run mode; no rules will be applied")
	default:
		e.backend = selectBackend(opts.Backend)
		if !e.backend.Available() {
			e.degraded = fmt.Sprintf("backend %s unavailable (nft: no binary or CAP_NET_ADMIN; netsh: not elevated)", e.backend.Name())
			slog.Warn("firewall gate degraded to noop", "backend", e.backend.Name())
			e.backend = NewNoop(false)
		} else if err := e.backend.Ensure(); err != nil {
			e.degraded = fmt.Sprintf("cannot prepare %s backend: %v", e.backend.Name(), err)
			slog.Warn("firewall gate degraded to noop", "err", err)
			e.backend = NewNoop(false)
		}
	}

	e.replayState()
	if _, noop := e.backend.(*NoopBackend); !noop {
		go e.sweepLoop()
	}
	return e
}

func selectBackend(name string) Backend {
	switch name {
	case "noop":
		return NewNoop(false)
	case "nft":
		return NewNft()
	case "netsh":
		return NewNetsh()
	case "auto", "":
		if runtime.GOOS == "windows" {
			return NewNetsh()
		}
		return NewNft()
	default:
		slog.Warn("unknown firewall backend, falling back to the platform default", "backend", name)
		return selectBackend("auto")
	}
}

// sweepEvery bounds how long an expired rule outlives its TTL.
const sweepEvery = 15 * time.Second

func (e *Engine) sweepLoop() {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for now := range t.C {
		e.Sweep(now)
	}
}

// Sweep removes rules whose TTL has passed. Windows firewall rules never
// expire on their own; nft elements do, but the engine must still forget them
// or they keep counting against the local detection cap (BlockedEntries).
func (e *Engine) Sweep(now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := 0
	for id, r := range e.applied {
		if r.TTL <= 0 || now.Before(r.CreatedAt.Add(r.TTL)) {
			continue
		}
		if err := e.backend.Remove(r); err != nil {
			slog.Warn("expired firewall rule not removed, retrying later", "rule", id, "err", err)
			continue
		}
		delete(e.applied, id)
		e.emit("firewall_rule_expired", r, "")
		removed++
	}
	if removed > 0 {
		e.persist()
	}
	return removed
}

// Enforcing reports whether rules really reach a firewall (not disabled,
// dry-run or degraded to noop).
func (e *Engine) Enforcing() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, noop := e.backend.(*NoopBackend)
	return !noop
}

func (e *Engine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := map[string]any{
		"enabled":   e.enabled,
		"dry_run":   e.dryRun,
		"backend":   e.backend.Name(),
		"available": e.backend.Available(),
		"rules":     len(e.applied),
		"protected": e.guard.ProtectedCIDRs(),
	}
	if e.degraded != "" {
		s["degraded"] = e.degraded
	}
	if err := e.guard.ResolveError(); err != nil {
		s["server_resolve_error"] = err.Error()
	}
	if nb, ok := e.backend.(*NoopBackend); ok {
		s["planned"] = nb.PlannedCommands()
	}
	return s
}

func (e *Engine) Add(rule Rule) (Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule = rule.normalize()
	if err := rule.Validate(); err != nil {
		e.emit("firewall_rule_rejected", rule, err.Error())
		return rule, err
	}
	if err := e.guard.Protect(rule); err != nil {
		e.emit("firewall_rule_rejected", rule, err.Error())
		return rule, err
	}
	if err := e.backend.Apply(rule); err != nil {
		e.emit("firewall_apply_failed", rule, err.Error())
		return rule, err
	}

	e.applied[rule.ID] = rule
	e.persist()
	e.emit("firewall_rule_applied", rule, "")
	return rule, nil
}

func (e *Engine) Remove(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, ok := e.applied[id]
	if !ok {
		return fmt.Errorf("no such rule %q", id)
	}
	if err := e.backend.Remove(rule); err != nil {
		return err
	}
	delete(e.applied, id)
	e.persist()
	e.emit("firewall_rule_removed", rule, "")
	return nil
}

func (e *Engine) List() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, 0, len(e.applied))
	for _, r := range e.applied {
		out = append(out, r)
	}
	return out
}

func (e *Engine) Flush() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.backend.Flush(); err != nil {
		return err
	}
	e.applied = make(map[string]Rule)
	e.persist()
	e.emit("firewall_flushed", Rule{}, "")
	return nil
}

func (e *Engine) Isolate() (map[string]any, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	protected := e.guard.ProtectedCIDRs()
	rule := Rule{
		Action:    ActionBlock,
		CIDR:      "0.0.0.0/0",
		Direction: DirBoth,
		Reason:    "isolate_host",
	}.normalize()

	if err := e.guard.Protect(rule); err == nil {
		return nil, fmt.Errorf("guard allowed 0.0.0.0/0 — refusing to isolate")
	}

	applied := make([]string, 0, len(protected))
	for _, c := range protected {
		allow := Rule{
			Action:    ActionAllow,
			CIDR:      c,
			Direction: DirBoth,
			Reason:    "isolate_allow",
		}.normalize()
		if err := e.backend.Apply(allow); err != nil {
			return nil, fmt.Errorf("apply allow %s: %w", c, err)
		}
		e.applied[allow.ID] = allow
		applied = append(applied, c)
	}

	block := Rule{
		Action:    ActionBlock,
		CIDR:      "0.0.0.0/0",
		Direction: DirInbound,
		Reason:    "isolate_host",
	}.normalize()
	if err := e.backend.Apply(block); err != nil {
		return nil, fmt.Errorf("apply isolation block: %w", err)
	}
	e.applied[block.ID] = block
	e.persist()
	e.emit("firewall_isolated", block, "")

	return map[string]any{
		"isolated":  true,
		"protected": applied,
		"backend":   e.backend.Name(),
	}, nil
}

func (e *Engine) Unisolate() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	blockID := Rule{Action: ActionBlock, CIDR: "0.0.0.0/0", Direction: DirInbound}.normalize().ID
	rule, ok := e.applied[blockID]
	if !ok {
		return fmt.Errorf("host is not isolated")
	}
	if err := e.backend.Remove(rule); err != nil {
		return err
	}
	delete(e.applied, blockID)

	for id, r := range e.applied {
		if r.Reason == "isolate_allow" {
			if err := e.backend.Remove(r); err == nil {
				delete(e.applied, id)
			}
		}
	}
	e.persist()
	e.emit("firewall_unisolated", rule, "")
	return nil
}

// ServerRule is the wire shape the server sends on every heartbeat: the full,
// declarative set of rules the agent should have. Sync reconciles towards it.
type ServerRule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
	Proto      string `json:"proto"`
	Port       int    `json:"port"`
	Direction  string `json:"direction"`
	TTLSeconds int    `json:"ttl_seconds"`
	Reason     string `json:"reason"`
}

// Sync makes the applied rule set match the server's list: rules absent from
// the server are removed, new ones are applied, and the guard still gets the
// final say on every addition. It is safe to call on every heartbeat.
func (e *Engine) Sync(rules []ServerRule) (added, removed int, rejected []string) {
	desired := make(map[string]ServerRule, len(rules))
	for _, r := range rules {
		desired[r.ID] = r
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for id, applied := range e.applied {
		if strings.HasPrefix(applied.Reason, "local:") {
			continue
		}
		if _, keep := desired[id]; keep {
			continue
		}
		if err := e.backend.Remove(applied); err != nil {
			slog.Warn("firewall sync remove failed", "rule", id, "err", err)
			continue
		}
		delete(e.applied, id)
		removed++
	}

	for id, r := range desired {
		if _, exists := e.applied[id]; exists {
			continue
		}
		rule := Rule{
			ID:        id,
			Action:    Action(r.Action),
			CIDR:      r.CIDR,
			Proto:     r.Proto,
			Port:      r.Port,
			Direction: Direction(r.Direction),
			TTL:       time.Duration(r.TTLSeconds) * time.Second,
			Reason:    "server:" + r.Reason,
		}.normalize()

		if err := rule.Validate(); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", id, err))
			e.emit("firewall_rule_rejected", rule, err.Error())
			continue
		}
		if err := e.guard.Protect(rule); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", id, err))
			e.emit("firewall_rule_rejected", rule, err.Error())
			continue
		}
		if err := e.backend.Apply(rule); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", id, err))
			e.emit("firewall_apply_failed", rule, err.Error())
			continue
		}
		e.applied[id] = rule
		added++
	}

	if added > 0 || removed > 0 {
		e.persist()
		slog.Info("firewall synced from server", "added", added, "removed", removed, "rejected", len(rejected))
	}
	return added, removed, rejected
}

func (e *Engine) RefreshGuard(serverURL string) {
	if serverURL != "" {
		e.guard.SetServerURL(serverURL)
		return
	}
	e.guard.Refresh()
}

func (e *Engine) emit(event string, rule Rule, errMsg string) {
	if e.buf == nil {
		return
	}
	line, _ := json.Marshal(map[string]any{
		"event":     event,
		"rule_id":   rule.ID,
		"action":    rule.Action,
		"cidr":      rule.CIDR,
		"proto":     rule.Proto,
		"port":      rule.Port,
		"direction": rule.Direction,
		"ttl":       rule.TTLSeconds(),
		"reason":    rule.Reason,
		"backend":   e.backend.Name(),
		"dry_run":   e.dryRun,
		"error":     errMsg,
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
	})
	e.buf.Push(tailer.Encode(eventLogType, string(line)))
}

type persistedRule struct {
	Rule
	ExpiresAt time.Time `json:"expires_at"`
}

func (e *Engine) persist() {
	if e.state == "" {
		return
	}
	out := make([]persistedRule, 0, len(e.applied))
	for _, r := range e.applied {
		p := persistedRule{Rule: r}
		if r.TTL > 0 {
			p.ExpiresAt = r.CreatedAt.Add(r.TTL)
		}
		out = append(out, p)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		slog.Warn("firewall state marshal failed", "err", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(e.state), 0o750); err != nil {
		slog.Warn("firewall state dir failed", "err", err)
		return
	}
	tmp := e.state + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		slog.Warn("firewall state write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, e.state); err != nil {
		slog.Warn("firewall state rename failed", "err", err)
	}
}

func (e *Engine) replayState() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.state == "" {
		return
	}
	data, err := os.ReadFile(e.state)
	if err != nil {
		return
	}
	var saved []persistedRule
	if err := json.Unmarshal(data, &saved); err != nil {
		slog.Warn("firewall state unreadable, ignoring", "err", err)
		return
	}

	now := time.Now().UTC()
	restored := 0
	for _, p := range saved {
		if !p.ExpiresAt.IsZero() && now.After(p.ExpiresAt) {
			continue
		}
		r := p.Rule.normalize()
		if err := e.guard.Protect(r); err != nil {
			slog.Warn("dropping persisted rule rejected by guard", "rule", r.ID, "err", err)
			continue
		}
		if err := e.backend.Apply(r); err != nil {
			slog.Warn("persisted rule reapply failed", "rule", r.ID, "err", err)
			continue
		}
		e.applied[r.ID] = r
		restored++
	}
	if restored > 0 {
		slog.Info("firewall state restored", "rules", restored)
		e.emit("firewall_state_restored", Rule{}, fmt.Sprintf("%d rules", restored))
	}
	e.persist()
}
