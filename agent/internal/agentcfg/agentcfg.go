// Package agentcfg applies the config overlay the dashboard sets per group
// and keeps a bad overlay from taking the agent down: it refuses a version
// the agent keeps crashing with, decides when a new version needs a restart,
// and falls back to the local server.url when the overlay's URL loses the
// server. Its state lives in StateFile in the state dir.
package agentcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/policy"
)

// StateFile is the name of the state file in the state dir.
const StateFile = "agent_config_state.json"

const (
	// crashWindow and crashStarts: this many starts of one version within
	// the window, without ever turning healthy, reject that version.
	crashWindow = 10 * time.Minute
	crashStarts = 3
	// contactTimeout is how long after boot an overlay server.url may go
	// without a first successful contact before the agent falls back to the
	// local URL.
	contactTimeout = 10 * time.Minute
	// maxRejected bounds the rejected list (oldest dropped first).
	maxRejected = 100
)

// now is the clock Boot uses; tests replace it.
var now = time.Now

type state struct {
	Version    string   `json:"version"`
	Starts     []int64  `json:"starts"`
	Healthy    bool     `json:"healthy"`
	Rejected   []string `json:"rejected"`
	RestartFor *string  `json:"restart_for,omitempty"` // nil: never asked; "" names the local config
}

// Runtime is the overlay state of the running agent. Its methods are safe
// for concurrent use.
type Runtime struct {
	// Now is the clock; tests replace it.
	Now func() time.Time

	path       string
	local      config.Config // config.yaml before the overlay
	bootTime   time.Time
	running    string // version applied at boot, "" for none
	urlSet     bool   // the running server.url comes from the overlay
	runningURL string

	// bootErr is the config error Boot found: the overlay warnings of the
	// running version, or the rejection of bootRejected (the version p asked
	// for at boot, which was refused; "" when none was).
	bootErr      string
	bootRejected string

	mu     sync.Mutex
	st     state
	errMsg string
	asked  bool // Want asked this process to restart (it has not yet)
}

// Boot applies the overlay of p to cfg unless that version is refused, and
// records the start. It must run before any module reads cfg. It never
// fails: state file errors are logged and the agent runs on.
func Boot(cfg *config.Config, stateDir string, p *policy.Policy) *Runtime {
	r := &Runtime{
		Now:   now,
		path:  filepath.Join(stateDir, StateFile),
		local: *cfg,
	}
	r.bootTime = r.Now()
	r.st = r.load()

	v := ""
	if p != nil {
		v = p.ConfigVersion
	}
	switch {
	case v == "":
	case slices.Contains(r.st.Rejected, v):
		r.errMsg = fmt.Sprintf("config %s rejected", v)
		r.bootRejected = v
	default:
		if r.st.Version != v {
			r.st.Version, r.st.Starts, r.st.Healthy = v, nil, false
		}
		r.st.Starts = recent(r.st.Starts, r.bootTime)
		if len(r.st.Starts) >= crashStarts && !r.st.Healthy {
			r.reject(v)
			r.errMsg = fmt.Sprintf("config %s rejected: agent kept failing to start", v)
			r.bootRejected = v
			slog.Warn("agentcfg: overlay rejected, booting local config", "version", v, "starts", len(r.st.Starts))
			break
		}
		r.st.Starts = append(r.st.Starts, r.bootTime.Unix())
		o := p.Settings.AgentConfig
		if w := config.ApplyOverlay(cfg, o); len(w) > 0 {
			r.errMsg = strings.Join(w, "; ")
			slog.Warn("agentcfg: overlay fields refused", "version", v, "warnings", r.errMsg)
		}
		r.running = v
		r.urlSet = o != nil && o.Server != nil && o.Server.URL != nil && cfg.Server.URL == *o.Server.URL
		slog.Info("agentcfg: overlay applied", "version", v)
	}
	r.runningURL = cfg.Server.URL
	r.bootErr = r.errMsg
	r.save()
	return r
}

// recent keeps the starts within crashWindow before t.
func recent(starts []int64, t time.Time) []int64 {
	var out []int64
	from, to := t.Add(-crashWindow).Unix(), t.Unix()
	for _, s := range starts {
		if s > from && s <= to {
			out = append(out, s)
		}
	}
	return out
}

// Status is the overlay version actually running ("" for none) and the
// last config error ("" for none), as the heartbeat reports them.
func (r *Runtime) Status() (version, errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running, r.errMsg
}

// restartRequiredMsg is the config error of an agent that needs a restart
// it cannot do itself.
const restartRequiredMsg = "restart required (not under a service manager)"

// RestartRequired records that a restart is needed but nothing would start
// the agent again (console mode). It goes after any error already reported,
// once; Want clears it when the policy is back on the running version.
func (r *Runtime) RestartRequired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case strings.Contains(r.errMsg, restartRequiredMsg):
	case r.errMsg == "":
		r.errMsg = restartRequiredMsg
	default:
		r.errMsg += "; " + restartRequiredMsg
	}
}

// OverlaySetsURL reports whether the running server.url comes from the
// overlay (the overlay set it and the agent accepted it).
func (r *Runtime) OverlaySetsURL() bool { return r.urlSet }

// MarkHealthy records that the running version stayed up; it is called
// after 10 minutes of uptime and ends the crash count of that version.
// It credits only the overlay version actually running: a healthy local run
// says nothing about a version that was not applied.
func (r *Runtime) MarkHealthy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running == "" || r.st.Version != r.running {
		return
	}
	r.st.Healthy, r.st.Starts = true, nil
	r.save()
}

// Want reports whether p needs a restart to take effect. A new server.url
// is probed first; a URL that fails rejects the version. A true result is
// recorded so that, if the restart does not bring the version in, the agent
// does not restart for it again.
func (r *Runtime) Want(p *policy.Policy, probe func(url string) error) (restart bool) {
	if p == nil {
		return false
	}
	v := p.ConfigVersion
	r.mu.Lock()
	switch {
	case v == r.running:
		// The wanted version is running again: errors about other versions
		// are stale. What remains is its own overlay warnings from boot. A
		// running version rejected since (lost contact) keeps its error.
		if !slices.Contains(r.st.Rejected, v) {
			r.errMsg = r.bootErr
			if r.bootRejected != "" {
				r.errMsg = ""
			}
		}
		r.mu.Unlock()
		return false
	case slices.Contains(r.st.Rejected, v):
		switch {
		case v == r.bootRejected:
			r.errMsg = r.bootErr
		case r.errMsg == "":
			r.errMsg = fmt.Sprintf("config %s rejected", v)
		}
		r.mu.Unlock()
		return false
	case r.st.RestartFor != nil && *r.st.RestartFor == v:
		// Asked in this process: the restart is still to come (jitter, or
		// console mode), not one that failed.
		if !r.asked {
			r.errMsg = fmt.Sprintf("config %s still differs after restart", v)
		}
		r.mu.Unlock()
		return false
	}
	r.mu.Unlock()

	// Going back to the local config needs no probe: it is the fallback.
	if v != "" && probe != nil {
		next := r.local
		config.ApplyOverlay(&next, p.Settings.AgentConfig)
		if u := next.Server.URL; u != r.runningURL {
			if err := probe(u); err != nil {
				r.mu.Lock()
				defer r.mu.Unlock()
				r.reject(v)
				r.errMsg = fmt.Sprintf("server.url %s unreachable: %v", u, err)
				r.save()
				slog.Warn("agentcfg: overlay rejected", "version", v, "err", r.errMsg)
				return false
			}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.st.RestartFor = &v
	r.asked = true
	r.save()
	return true
}

// CheckContact reports whether the agent must restart because the overlay's
// server.url never reached the server: no successful contact (lastOK) since
// this boot, 10 minutes after it. The version is then rejected so the next
// boot uses the local URL. Once a contact succeeded after boot the URL
// works, and a later outage never drops the overlay. A lastOK from before
// the boot (a previous process) counts as no contact.
func (r *Runtime) CheckContact(lastOK time.Time) (restart bool) {
	// An overlay URL equal to the local one has nothing to fall back to.
	if !r.urlSet || r.runningURL == r.local.Server.URL {
		return false
	}
	if !lastOK.IsZero() && !lastOK.Before(r.bootTime) {
		return false
	}
	if r.Now().Sub(r.bootTime) <= contactTimeout {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reject(r.running)
	r.errMsg = fmt.Sprintf("server.url %s unreachable: no contact for %s", r.runningURL, contactTimeout)
	r.save()
	slog.Warn("agentcfg: overlay server.url lost the server, falling back", "version", r.running, "url", r.runningURL)
	return true
}

// reject adds v to the rejected list; r.mu must be held (or r unshared).
func (r *Runtime) reject(v string) {
	if v == "" || slices.Contains(r.st.Rejected, v) {
		return
	}
	r.st.Rejected = append(r.st.Rejected, v)
	if n := len(r.st.Rejected); n > maxRejected {
		r.st.Rejected = slices.Clone(r.st.Rejected[n-maxRejected:])
	}
}

func (r *Runtime) load() state {
	var st state
	b, err := os.ReadFile(r.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("agentcfg: cannot read state, starting fresh", "path", r.path, "err", err)
		}
		return st
	}
	if err := json.Unmarshal(b, &st); err != nil {
		slog.Warn("agentcfg: corrupt state, starting fresh", "path", r.path, "err", err)
		return state{}
	}
	return st
}

// save writes the state atomically (tmp file, then rename); r.mu must be
// held (or r unshared). Failures are logged only.
func (r *Runtime) save() {
	b, err := json.Marshal(r.st)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(r.path), 0o750)
	}
	tmp := r.path + ".tmp"
	if err == nil {
		err = os.WriteFile(tmp, b, 0o640)
	}
	if err == nil {
		if err = os.Rename(tmp, r.path); err != nil {
			os.Remove(tmp)
		}
	}
	if err != nil {
		slog.Warn("agentcfg: cannot save state", "path", r.path, "err", err)
	}
}
