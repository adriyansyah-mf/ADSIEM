// Package policy is the group protection policy from the server
// (server-api services/agent_policy.py): which protections run, and the
// exclusions each one honours. Linux and Windows read the same policy.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Path is the agent endpoint that returns this agent's group policy.
const Path = "/api/ingest/policy"

// FileName is the saved policy in the state directory.
const FileName = "policy.json"

// Scopes an exclusion can apply to.
const (
	ScopePrevention = "prevention"
	ScopeMalware    = "malware"
	ScopeYara       = "yara"
	ScopeRansomware = "ransomware"
	ScopeScript     = "script"
	ScopeML         = "ml"
)

// Exclusion: Kind path_prefix, image (full path, or a file name in any
// folder), sha256 or command_line (substring).
type Exclusion struct {
	Kind   string   `json:"kind"`
	Value  string   `json:"value"`
	Scopes []string `json:"scopes"`
}

// Settings are the policy's switches and exclusions.
type Settings struct {
	PreventionEnabled bool   `json:"prevention_enabled"`
	YaraOnAccess      bool   `json:"yara_on_access"`
	RansomwareMode    string `json:"ransomware_mode"` // off, report, stop
	RansomwareIsolate bool   `json:"ransomware_isolate"`
	NotifyUser        bool   `json:"notify_user"`
	ScriptScan        string `json:"script_scan"` // off, detect, block
	// MLAction: the static ML check of scanned files (internal/mlscan):
	// off, detect or block (quarantine malicious files); empty (a server
	// from before it) is detect.
	MLAction string `json:"ml_action"`
	// QuickScanTime "HH:MM" (every day) and FullScanSchedule "<day> HH:MM"
	// or "daily HH:MM": scheduled file scans (internal/fullscan); "" is off.
	QuickScanTime    string      `json:"quick_scan_time"`
	FullScanSchedule string      `json:"full_scan_schedule"`
	Exclusions       []Exclusion `json:"exclusions"`
}

// Policy is one version of the settings.
type Policy struct {
	Group    string   `json:"group"`
	Version  string   `json:"version"`
	Settings Settings `json:"settings"`
}

// Default is what runs before the first policy arrives: everything on, as
// before policies existed.
func Default() *Policy {
	return &Policy{Group: "built-in", Settings: Settings{PreventionEnabled: true, YaraOnAccess: true,
		RansomwareMode: "stop", NotifyUser: true, ScriptScan: "detect", MLAction: "detect"}}
}

// fold: Windows paths compare case-insensitively.
var fold = runtime.GOOS == "windows"

func norm(s string) string {
	if fold {
		return strings.ToLower(s)
	}
	return s
}

func base(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Match is what is checked against an exclusion; empty fields never match.
type Match struct {
	Image, Path, SHA256, CommandLine string
}

func (e Exclusion) has(scope string) bool {
	for _, s := range e.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (e Exclusion) matches(m Match) bool {
	v := e.Value
	switch e.Kind {
	case "image":
		if m.Image == "" {
			return false
		}
		if strings.ContainsAny(v, `/\`) {
			return norm(m.Image) == norm(v)
		}
		return strings.EqualFold(base(m.Image), v)
	case "path_prefix":
		for _, p := range []string{m.Path, m.Image} {
			if p != "" && strings.HasPrefix(norm(p), norm(v)) {
				return true
			}
		}
	case "sha256":
		return m.SHA256 != "" && strings.EqualFold(m.SHA256, v)
	case "command_line":
		return m.CommandLine != "" && strings.Contains(strings.ToLower(m.CommandLine), strings.ToLower(v))
	}
	return false
}

// Excluded reports whether an exclusion with scope matches.
func (s Settings) Excluded(scope string, m Match) bool {
	for _, e := range s.Exclusions {
		if e.has(scope) && e.matches(m) {
			return true
		}
	}
	return false
}

// For keeps the exclusions of one scope (what the fanotify helper needs).
func (s Settings) For(scope string) []Exclusion {
	var out []Exclusion
	for _, e := range s.Exclusions {
		if e.has(scope) {
			out = append(out, e)
		}
	}
	return out
}

// ─── store and sync ──────────────────────────────────────────────────

// Poster is the part of client.Client the sync needs.
type Poster interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

// Store holds the policy in force and follows the version heartbeats name.
type Store struct {
	path string
	cur  atomic.Pointer[Policy]

	mu       sync.Mutex
	want     string
	wantSet  bool
	wake     chan struct{}
	onChange []func(*Policy)
}

// Open loads the saved policy (else Default).
func Open(path string) *Store {
	s := &Store{path: path, wake: make(chan struct{}, 1)}
	p := Default()
	if b, err := os.ReadFile(path); err == nil {
		var saved Policy
		if json.Unmarshal(b, &saved) == nil && saved.Version != "" {
			p = &saved
			slog.Info("policy: loaded", "group", p.Group, "version", p.Version)
		}
	}
	s.cur.Store(p)
	return s
}

// Current is the policy in force.
func (s *Store) Current() *Policy { return s.cur.Load() }

// OnChange registers f, called with every new policy and once now.
func (s *Store) OnChange(f func(*Policy)) {
	s.mu.Lock()
	s.onChange = append(s.onChange, f)
	s.mu.Unlock()
	f(s.Current())
}

// Want records the version the heartbeat names ("" from an older server:
// the current policy stays).
func (s *Store) Want(version string) {
	if version == "" {
		return
	}
	s.mu.Lock()
	s.want, s.wantSet = version, true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Store) needed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wantSet && s.want != s.Current().Version
}

// SyncLoop fetches the policy whenever the wanted version differs, retrying
// every minute, until ctx ends.
func (s *Store) SyncLoop(ctx context.Context, c Poster) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if s.needed() {
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := s.Sync(sctx, c); err != nil {
				slog.Warn("policy: could not fetch, will retry", "err", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
	}
}

// Sync fetches and installs the policy.
func (s *Store) Sync(ctx context.Context, c Poster) error {
	resp, err := c.PostContext(ctx, Path, map[string]any{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", Path, resp.StatusCode)
	}
	var p Policy
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&p); err != nil {
		return fmt.Errorf("%s: %w", Path, err)
	}
	s.install(&p)
	return nil
}

func (s *Store) install(p *Policy) {
	if b, err := json.Marshal(p); err == nil {
		tmp := s.path + ".tmp"
		if os.MkdirAll(filepath.Dir(s.path), 0o750) == nil && os.WriteFile(tmp, b, 0o640) == nil {
			os.Rename(tmp, s.path)
		}
	}
	s.cur.Store(p)
	slog.Info("policy: applied", "group", p.Group, "version", p.Version, "prevention", p.Settings.PreventionEnabled,
		"yara", p.Settings.YaraOnAccess, "ransomware", p.Settings.RansomwareMode, "exclusions", len(p.Settings.Exclusions))
	s.mu.Lock()
	fs := append([]func(*Policy){}, s.onChange...)
	s.mu.Unlock()
	for _, f := range fs {
		f(p)
	}
}
