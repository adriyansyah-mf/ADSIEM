package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Host isolation contains an infected machine: nothing in or out, IPv4 and
// IPv6, connections already open included, except what keeps it manageable
// (the SIEM server, loopback, link-local, the gateway, DNS, DHCP). It is a
// mechanism of its own in each backend (an nft table, the Windows Firewall
// profile policy), not block rules: a block rule only stopped new inbound
// connections, so an "isolated" host kept talking to its C2.
//
// Safety, since the agent must stay reachable to be released:
//   - refused while the server's address has never been resolved;
//   - the server's last good addresses are kept when a lookup fails;
//   - re-resolved every minute while isolated, the allow list updated;
//   - released by itself when the server has been unreachable for
//     ReleaseAfterOffline (a broken isolation must not strand the host);
//   - kept across agent restarts (a state file next to the rules').

// isolator is a backend that can isolate the host. Isolate replaces the
// allow list when the host is already isolated.
type isolator interface {
	Isolate(allow []string) error
	Unisolate() error
}

// ErrNotEnforcing: the firewall is off, in dry-run or has no backend, so an
// isolation would block nothing. Callers must not report the host isolated.
var ErrNotEnforcing = errors.New("firewall not enforcing on this agent: isolation would block nothing")

const (
	isolateRefreshEvery   = time.Minute
	defaultReleaseOffline = 60 * time.Minute
)

type isolationState struct {
	Since time.Time `json:"since"`
	Allow []string  `json:"allow"`
	// pending: wanted (restored at start) but not applied yet, because the
	// backend failed or the server's address is unknown; the monitor
	// retries every minute.
	pending bool
}

// Isolate isolates the host. The result lists what stays reachable.
func (e *Engine) Isolate() (map[string]any, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.guard.HasServer() {
		return nil, fmt.Errorf("refusing to isolate: the SIEM server's address is unknown (%v); "+
			"isolating would cut the agent off from the server and from the command that releases it",
			e.guard.ResolveError())
	}
	allow := e.guard.IsolationAllow()
	iso, ok := e.backend.(isolator)
	if !ok {
		if e.dryRun {
			return map[string]any{"isolated": false, "dry_run": true, "would_allow": allow,
				"backend": e.backend.Name()}, nil
		}
		return nil, ErrNotEnforcing
	}
	if err := iso.Isolate(allow); err != nil {
		return nil, fmt.Errorf("isolate: %w", err)
	}
	since := time.Now().UTC()
	if e.isolation != nil {
		since = e.isolation.Since
	}
	e.isolation = &isolationState{Since: since, Allow: allow}
	e.isolatedAt = time.Now()
	e.persistIsolation()
	e.emit("firewall_isolated", isolationRule(), "")
	e.startIsolationMonitor()
	return map[string]any{"isolated": true, "protected": allow, "backend": e.backend.Name(),
		"direction": DirBoth, "ipv6": true}, nil
}

// Unisolate releases the host.
func (e *Engine) Unisolate() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.unisolateLocked("")
}

func (e *Engine) unisolateLocked(why string) error {
	iso, ok := e.backend.(isolator)
	if !ok {
		return ErrNotEnforcing
	}
	if err := iso.Unisolate(); err != nil {
		return err
	}
	if e.isolation == nil {
		// nothing recorded (state file lost, agent crashed or reinstalled):
		// the backend's isolation is removed all the same
		return nil
	}
	e.isolation = nil
	e.stopIsolationMonitor()
	e.persistIsolation()
	e.emit("firewall_unisolated", isolationRule(), why)
	return nil
}

// Isolated reports whether the host is isolated.
func (e *Engine) Isolated() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isolation != nil
}

func isolationRule() Rule {
	return Rule{Action: ActionBlock, CIDR: "0.0.0.0/0,::/0", Direction: DirBoth, Reason: "isolate_host"}
}

// startIsolationMonitor runs while isolated (e.mu held by the caller).
func (e *Engine) startIsolationMonitor() {
	if e.monitorStop != nil {
		return
	}
	stop := make(chan struct{})
	e.monitorStop = stop
	every := e.refreshEvery
	if every <= 0 {
		every = isolateRefreshEvery
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				e.isolationTick(now)
			}
		}
	}()
}

func (e *Engine) stopIsolationMonitor() {
	if e.monitorStop != nil {
		close(e.monitorStop)
		e.monitorStop = nil
	}
}

// isolationTick re-resolves the server (its address may change while the
// host is isolated) and releases the host when the server has been
// unreachable for too long.
func (e *Engine) isolationTick(now time.Time) {
	e.guard.Refresh()
	allow := e.guard.IsolationAllow()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isolation == nil {
		return
	}
	if e.releaseAfter > 0 && e.lastContact != nil {
		last := e.lastContact()
		if last.Before(e.isolatedAt) {
			last = e.isolatedAt // count from the isolation (or the agent's restart), not an older contact
		}
		if now.Sub(last) > e.releaseAfter {
			slog.Warn("releasing host isolation: the SIEM server has been unreachable",
				"for", now.Sub(last).Round(time.Second), "limit", e.releaseAfter)
			if err := e.unisolateLocked("server unreachable for " + e.releaseAfter.String()); err != nil {
				slog.Warn("could not release isolation", "err", err)
			}
			return
		}
	}
	if e.isolation.pending {
		if !e.guard.HasServer() {
			return // isolating now would cut the host off for good
		}
		if iso, ok := e.backend.(isolator); ok {
			if err := iso.Isolate(allow); err != nil {
				slog.Warn("host isolation still not restored", "err", err)
				return
			}
			e.isolation.Allow, e.isolation.pending = allow, false
			e.persistIsolation()
			e.emit("firewall_isolation_restored", isolationRule(), "")
		}
		return
	}
	if !slices.Equal(allow, e.isolation.Allow) {
		if iso, ok := e.backend.(isolator); ok {
			if err := iso.Isolate(allow); err != nil {
				slog.Warn("isolation allow list update failed", "err", err)
				return
			}
			e.isolation.Allow = allow
			e.persistIsolation()
		}
	}
}

func (e *Engine) isolationPath() string {
	if e.state == "" {
		return ""
	}
	return e.state + ".isolation.json"
}

func (e *Engine) persistIsolation() {
	path := e.isolationPath()
	if path == "" {
		return
	}
	if e.isolation == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("firewall isolation state remove failed", "err", err)
		}
		return
	}
	data, err := json.Marshal(e.isolation)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		slog.Warn("firewall isolation state dir failed", "err", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		slog.Warn("firewall isolation state write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		slog.Warn("firewall isolation state rename failed", "err", err)
	}
}

// restoreIsolation re-applies an isolation that was in force when the agent
// stopped (or the old block-rule isolation of an earlier version).
func (e *Engine) restoreIsolation(legacy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var st isolationState
	found := legacy
	if path := e.isolationPath(); path != "" {
		if data, err := os.ReadFile(path); err == nil && json.Unmarshal(data, &st) == nil {
			found = true
		}
	}
	if !found {
		return
	}
	iso, ok := e.backend.(isolator)
	if !ok {
		slog.Warn("host was isolated, but the firewall cannot enforce isolation now")
		return
	}
	if st.Since.IsZero() {
		st.Since = time.Now().UTC()
	}
	e.isolation = &isolationState{Since: st.Since}
	e.isolatedAt = time.Now()
	e.startIsolationMonitor()

	allow := e.guard.IsolationAllow()
	if !e.guard.HasServer() {
		if len(st.Allow) == 0 {
			// no server address now or saved (an old isolation): wait for one
			slog.Warn("host isolation pending: the SIEM server's address is unknown")
			e.isolation.pending = true
			e.persistIsolation()
			return
		}
		allow = mergeAllow(allow, st.Allow) // offline at start: the last good list keeps the server
	}
	if err := iso.Isolate(allow); err != nil {
		slog.Warn("could not restore host isolation, retrying every minute", "err", err)
		e.isolation.Allow, e.isolation.pending = st.Allow, true
		e.persistIsolation()
		return
	}
	e.isolation.Allow = allow
	e.persistIsolation()
	e.emit("firewall_isolation_restored", isolationRule(), "")
}

func mergeAllow(a, b []string) []string {
	out := slices.Clone(a)
	for _, c := range b {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}
