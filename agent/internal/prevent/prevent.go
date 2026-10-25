package prevent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LogType of decision lines (decoders/linux_exec_prevention.yaml).
const LogType = "linux_exec_prevention"

// RulesPath is the agent endpoint that returns the enabled rules.
const RulesPath = "/api/ingest/prevention-rules"

const pollEvery = time.Minute

// Decision is one execution a rule matched.
type Decision struct {
	Rule    *compiled
	Blocked bool
	Engine  string // lsm or fanotify
	Path    string
	Parent  string
	SHA256  string
	Comm    string
	PID     uint32
	PPID    uint32
	UID     uint32
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func (d Decision) line() string {
	action := "detected"
	if d.Blocked {
		action = "blocked"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `action=%s rule=%s rule_id=%s rule_type=%s engine=%s Image=%s ParentImage=%s`,
		action, kv(d.Rule.Name), kv(d.Rule.ID), d.Rule.RuleType, d.Engine, kv(d.Path), kv(d.Parent))
	if d.SHA256 != "" {
		fmt.Fprintf(&sb, ` SHA256=%s`, d.SHA256)
	}
	fmt.Fprintf(&sb, ` Comm=%s PID=%d PPID=%d User=%d`, kv(d.Comm), d.PID, d.PPID, d.UID)
	return sb.String()
}

// engines is the platform part: the BPF LSM and fanotify engines on Linux.
type engines interface {
	apply(p *Policy)
	close()
}

// Options configure the Manager.
type Options struct {
	// Push receives one line per decision.
	Push func(logType, line string)
}

// Manager keeps the server's rules applied to the engines.
type Manager struct {
	opts   Options
	eng    engines
	mu     sync.Mutex
	hash   string
	policy *Policy
	last   map[string]time.Time // decision dedupe
	lastMu sync.Mutex
}

// Start starts the platform engines; it fails where there are none.
func Start(opts Options) (*Manager, error) {
	m := &Manager{opts: opts, last: map[string]time.Time{}}
	eng, err := startEngines(m.report)
	if err != nil {
		return nil, err
	}
	m.eng = eng
	return m, nil
}

func (m *Manager) Close() { m.eng.close() }

// Hash is the version of the applied rule set.
func (m *Manager) Hash() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hash
}

// Apply compiles and enforces rules; invalid ones are logged and skipped.
func (m *Manager) Apply(hash string, rules []Rule) {
	p, errs := Compile(rules)
	for _, e := range errs {
		slog.Warn("prevent: rule", "err", e)
	}
	m.mu.Lock()
	m.hash, m.policy = hash, p
	m.mu.Unlock()
	m.eng.apply(p)
	blocking := 0
	for _, c := range p.Rules {
		if c.block {
			blocking++
		}
	}
	slog.Info("prevent: rules applied", "rules", len(p.Rules), "blocking", blocking, "errors", len(errs))
}

// report pushes a decision line; the same rule, image and parent are
// reported at most once a minute (a blocked loop would flood otherwise).
func (m *Manager) report(d Decision) {
	key := fmt.Sprintf("%d|%s|%s|%t", d.Rule.index, d.Path, d.Parent, d.Blocked)
	m.lastMu.Lock()
	now := time.Now()
	if t, ok := m.last[key]; ok && now.Sub(t) < time.Minute {
		m.lastMu.Unlock()
		return
	}
	if len(m.last) > 10000 {
		m.last = map[string]time.Time{}
	}
	m.last[key] = now
	m.lastMu.Unlock()
	m.opts.Push(LogType, d.line())
}

// Poster is the part of client.Client the poll loop needs.
type Poster interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

type rulesResponse struct {
	Hash      string `json:"hash"`
	Unchanged bool   `json:"unchanged"`
	Rules     []Rule `json:"rules"`
}

// Sync fetches the rules once; the server answers "unchanged" when the
// agent already has the current set.
func (m *Manager) Sync(ctx context.Context, c Poster) error {
	resp, err := c.PostContext(ctx, RulesPath, map[string]any{"loaded_hash": m.Hash()})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", RulesPath, resp.StatusCode)
	}
	var body rulesResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return fmt.Errorf("%s: %w", RulesPath, err)
	}
	if body.Unchanged && body.Hash == m.Hash() {
		return nil
	}
	m.Apply(body.Hash, body.Rules)
	return nil
}

// Run polls the server for rule changes and re-applies the policy (a
// rule's directory may have been recreated) until ctx ends.
func (m *Manager) Run(ctx context.Context, c Poster) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := m.Sync(sctx, c); err != nil {
			slog.Warn("prevent: could not fetch rules, will retry", "err", err)
		} else {
			m.mu.Lock()
			p := m.policy
			m.mu.Unlock()
			if p != nil {
				m.eng.apply(p)
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
