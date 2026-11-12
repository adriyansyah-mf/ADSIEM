package prevent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/malhash"
	"github.com/siem-platform/agent/internal/policy"
	"github.com/siem-platform/agent/internal/rulecache"
)

// LogType of decision lines on Linux (decoders/linux_exec_prevention.yaml);
// WindowsLogType on Windows (decoders/windows_exec_prevention.yaml).
const (
	LogType        = "linux_exec_prevention"
	WindowsLogType = "windows_exec_prevention"
)

// decisionLogType is LogType, or WindowsLogType where the Windows engine runs.
var decisionLogType = LogType

// RulesPath is the agent endpoint that returns the enabled rules.
const RulesPath = "/api/ingest/prevention-rules"

const pollEvery = time.Minute

// Decision is one execution a rule matched.
type Decision struct {
	Rule    *compiled
	Blocked bool
	// Terminated: the program started and was stopped right after (Windows:
	// no driver, so no veto before it runs). Error says why a block failed.
	Terminated bool
	Error      string
	Engine     string // lsm, fanotify or etw
	Path       string
	Parent     string
	SHA256     string
	Comm       string
	PID        uint32
	PPID       uint32
	UID        uint32
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func (d Decision) line() string {
	action := "detected"
	switch {
	case d.Blocked:
		action = "blocked"
	case d.Terminated:
		action = "terminated"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, `action=%s rule=%s rule_id=%s rule_type=%s engine=%s Image=%s ParentImage=%s`,
		action, kv(d.Rule.Name), kv(d.Rule.ID), d.Rule.RuleType, d.Engine, kv(d.Path), kv(d.Parent))
	if d.SHA256 != "" {
		fmt.Fprintf(&sb, ` SHA256=%s`, d.SHA256)
	}
	fmt.Fprintf(&sb, ` Comm=%s PID=%d PPID=%d User=%d`, kv(d.Comm), d.PID, d.PPID, d.UID)
	if d.Error != "" {
		fmt.Fprintf(&sb, ` Error=%s`, kv(d.Error))
	}
	return sb.String()
}

// malwareEvent is a known-malware decision as a malhash line.
func (d Decision) malwareEvent() malhash.Event {
	action := "detected"
	switch {
	case d.Blocked:
		action = "blocked"
	case d.Terminated:
		action = "terminated"
	}
	return malhash.Event{Action: action, Trigger: "exec", Label: d.Rule.Name, SHA256: d.SHA256, Path: d.Path,
		Parent: d.Parent, Engine: d.Engine, PID: d.PID, PPID: d.PPID, UID: d.UID, Error: d.Error}
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
	// CacheFile keeps the last rule set from the server, enforced at start
	// until the server answers (internal/rulecache). Empty: no cache.
	CacheFile string
}

// Manager keeps the server's rules applied to the engines.
type Manager struct {
	opts   Options
	eng    engines
	mu     sync.Mutex
	hash   string
	policy *Policy
	// known-malware set (internal/malhash) every policy also checks
	malware     *malhash.Set
	malwareFile string
	// group policy (internal/policy): prevention off, exclusions
	off        bool
	exclusions []policy.Exclusion
	last       map[string]time.Time // decision dedupe
	lastMu     sync.Mutex
}

// Start starts the platform engines; it fails where there are none.
func Start(opts Options) (*Manager, error) {
	m := &Manager{opts: opts, last: map[string]time.Time{}}
	eng, err := startEngines(m.report)
	if err != nil {
		return nil, err
	}
	m.eng = eng
	m.loadCache()
	return m, nil
}

// loadCache enforces the rules cached by the last sync: an agent that
// starts while the server is unreachable must not run without them.
func (m *Manager) loadCache() {
	if m.opts.CacheFile == "" {
		return
	}
	var rules []Rule
	hash, err := rulecache.Load(m.opts.CacheFile, &rules)
	if err != nil {
		if !errors.Is(err, rulecache.ErrNone) {
			slog.Warn("prevent: cached rules not used", "err", err)
		}
		return
	}
	slog.Info("prevent: enforcing cached rules until the server answers", "rules", len(rules))
	m.Apply(hash, rules)
}

func (m *Manager) Close() { m.eng.close() }

// ProcessStart is a new process as a process sensor reports it (Windows ETW).
type ProcessStart struct {
	PID, PPID   uint32
	Image       string // full path
	ParentImage string
}

// execObserver is an engine fed by a process sensor rather than the kernel.
type execObserver interface {
	observe(ProcessStart)
}

// ObserveExec hands a process start to an engine that decides after the
// fact (Windows); a no-op where the kernel decides (Linux).
func (m *Manager) ObserveExec(p ProcessStart) {
	if o, ok := m.eng.(execObserver); ok {
		o.observe(p)
	}
}

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
	p = p.withMalware(m.malware, m.malwareFile)
	m.hash, m.policy = hash, p
	enforced := m.gated(p)
	m.mu.Unlock()
	m.eng.apply(enforced)
	blocking := 0
	for _, c := range p.Rules {
		if c.block {
			blocking++
		}
	}
	slog.Info("prevent: rules applied", "rules", len(p.Rules), "blocking", blocking, "errors", len(errs))
}

// SetKnownMalware makes every exec also be checked against set (saved in
// file, where the Linux fanotify helper loads it). Detect or block comes
// from the set's action; nothing is checked when it is off or empty.
func (m *Manager) SetKnownMalware(set *malhash.Set, file string) {
	m.mu.Lock()
	m.malware, m.malwareFile = set, file
	p := m.policy
	if p == nil {
		p, _ = Compile(nil) // no rules fetched yet
	}
	p = p.withMalware(set, file)
	m.policy = p
	enforced := m.gated(p)
	m.mu.Unlock()
	m.eng.apply(enforced)
	slog.Info("prevent: known-malware hashes applied", "hashes", set.Len(), "action", set.Action)
}

// SetGate applies the group policy: off stops enforcing and reporting
// every rule and the known-malware check; exclusions (prevention and
// malware scopes) are honoured by what is decided in user space.
func (m *Manager) SetGate(off bool, exclusions []policy.Exclusion) {
	m.mu.Lock()
	m.off, m.exclusions = off, exclusions
	p := m.policy
	if p == nil {
		p, _ = Compile(nil)
		p = p.withMalware(m.malware, m.malwareFile)
		m.policy = p
	}
	enforced := m.gated(p)
	m.mu.Unlock()
	m.eng.apply(enforced)
	slog.Info("prevent: group policy applied", "off", off, "exclusions", len(exclusions))
}

// gated is what the engines enforce: nothing while the group policy turns
// prevention off (so the BPF LSM rules are emptied too), else p with the
// policy's exclusions. m.mu held.
func (m *Manager) gated(p *Policy) *Policy {
	if m.off {
		return (&Policy{hashes: map[string]*compiled{}, paths: map[string]*compiled{}}).withGate(true, nil)
	}
	return p.withGate(false, m.exclusions)
}

// report pushes a decision line; the same rule, image and parent are
// reported at most once a minute (a blocked loop would flood otherwise).
func (m *Manager) report(d Decision) {
	key := fmt.Sprintf("%d|%s|%s|%s|%t|%t", d.Rule.index, d.Rule.ID, d.Path, d.Parent, d.Blocked, d.Terminated)
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
	if d.Rule.RuleType == TypeKnownMalware {
		m.opts.Push(malhash.LogType, d.malwareEvent().Line())
		return
	}
	m.opts.Push(decisionLogType, d.line())
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
	if m.opts.CacheFile != "" {
		if err := rulecache.Save(m.opts.CacheFile, body.Hash, body.Rules); err != nil {
			slog.Warn("prevent: could not cache rules", "err", err)
		}
	}
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
			var p *Policy
			if m.policy != nil {
				p = m.gated(m.policy)
			}
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
