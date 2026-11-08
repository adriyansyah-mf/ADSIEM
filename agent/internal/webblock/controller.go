package webblock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// reapplyEvery is how often Run re-checks the hosts block and retries
// whatever a previous Apply could not finish.
const reapplyEvery = 5 * time.Minute

// maxLastError bounds Health.LastError (the server keeps at most 300 chars).
const maxLastError = 280

// retryStartOnTimer lets the 5-minute re-check retry a page server that did
// not start. Not on Linux: the agent never binds a privileged port on a
// timer there (it could take the port from a service that starts later); a
// failed start is retried only when the list, page or CA changes.
var retryStartOnTimer = runtime.GOOS != "linux"

// Health is the web protection state the heartbeat reports.
type Health struct {
	Enabled       bool   `json:"enabled"`
	Entries       int    `json:"entries"`
	Version       string `json:"version"`
	Group         string `json:"group"`
	CAInstalled   bool   `json:"ca_installed"`
	CAFingerprint string `json:"ca_fingerprint"`
	PageServer    string `json:"page_server"`
	HostsTampered bool   `json:"hosts_tampered"`
	LastError     string `json:"last_error"`
}

// caProvider is implemented by an Authority that can hand the page server the
// CA it installed (TrustStore does).
type caProvider interface{ CA() *CA }

// snapshot is what the running page server and the CA consult; it is swapped
// whole on every Apply so listeners never see a half-updated list.
type snapshot struct {
	selected map[string]bool
	entries  map[string]Entry
}

func (s *snapshot) base(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if s.selected[host] {
		return host, true
	}
	if a := strings.TrimPrefix(host, "www."); a != host && s.selected[a] {
		return a, true
	}
	return "", false
}

// Controller turns the blocklist into enforcement: hosts block, CA and block
// page server. Apply is idempotent; only what differs from the last Apply is
// redone.
type Controller struct {
	Hosts     Hosts
	Authority Authority
	Server    PageServer
	Hostname  string
	// StateDir is where <StateDir>/webblock holds the CA files; used to tell
	// whether an inactive start has anything of ours to remove.
	StateDir string

	mu sync.Mutex
	// what the last Apply left in place
	off        bool   // everything removed
	caOK       bool   // CA installed and handed to the server
	ca         *CA    // the CA Ensure installed
	startCA    *CA    // the CA the running server was started with
	started    bool   // Server.Start succeeded
	startPage  string // page and contact the server runs with
	startCont  string
	startVer   string // list version of the last Start
	startTried bool   // Server.Start ran since the last deactivate
	ipv6       bool   // [::1] listeners are up
	hostsOK    bool   // Hosts.Apply succeeded for hostsKey
	hostsKey   string // selected domains and ipv6 last written
	snap       atomic.Pointer[snapshot]
	health     Health // working copy, under mu
	// published is what Health returns; stored at the end of every apply so
	// the heartbeat never waits for an Apply running trust tools.
	published atomic.Pointer[Health]
}

// Apply enforces l. It never panics; failures are recorded in Health.LastError.
func (c *Controller) Apply(l *List) { c.apply(l, false) }

// ApplyCurrent enforces the list current() returns, read under the controller
// lock at execution time, so a caller that waited for the lock never applies a
// list older than one applied meanwhile. force also rewrites the hosts block.
func (c *Controller) ApplyCurrent(current func() *List) { c.applyCurrent(current, false) }

func (c *Controller) applyCurrent(current func() *List, force bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applyLocked(current(), force)
}

// Stop shuts the page server down, which removes the block page redirect. The
// hosts block stays: blocked names then get "connection refused" on the sink
// instead of a free high port any local user could bind. It does not wait for
// a running Apply.
func (c *Controller) Stop() { c.Server.Stop() }

// reapply is Apply that also rewrites the hosts block (a no-op on disk when
// the file is already right) so a tampered or removed block is repaired.
func (c *Controller) reapply(l *List) { c.apply(l, true) }

func (c *Controller) apply(l *List, force bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applyLocked(l, force)
}

func (c *Controller) applyLocked(l *List, force bool) {
	defer c.publish()
	defer func() {
		if r := recover(); r != nil {
			c.health.LastError = clipError(fmt.Sprintf("web protection: %v", r))
			slog.Error("webblock: apply panicked", "panic", r)
		}
	}()
	if l == nil {
		l = Empty()
	}
	if !l.Active() {
		c.deactivate(l)
		return
	}
	c.activate(l, force)
}

func (c *Controller) deactivate(l *List) {
	if c.off {
		return
	}
	var errs []error
	if err := c.Hosts.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("hosts: %w", err))
	}
	c.Server.Stop()
	if c.caOK || c.Authority.Installed() || c.caFilesExist() {
		if err := c.Authority.Remove(); err != nil {
			errs = append(errs, fmt.Errorf("ca: %w", err))
		}
	}
	c.off = len(errs) == 0
	c.caOK, c.ca, c.startCA, c.started, c.hostsOK, c.hostsKey = false, nil, nil, false, false, ""
	c.startTried, c.startVer, c.startPage, c.startCont = false, "", "", ""
	c.snap.Store(nil)
	c.health = Health{Version: l.Version, Group: l.Group}
	c.setErr(errs)
}

// caFilesExist reports CA files left by an earlier run (the directory alone
// may only hold the saved list).
func (c *Controller) caFilesExist() bool {
	if c.StateDir == "" {
		return false
	}
	for _, n := range []string{CACertFile, CAKeyFile} {
		if _, err := os.Lstat(filepath.Join(caDir(c.StateDir), n)); err == nil {
			return true
		}
	}
	return false
}

// clipError cuts an error to maxLastError runes, marking the cut.
func clipError(s string) string {
	if utf8.RuneCountInString(s) <= maxLastError {
		return s
	}
	r := []rune(s)
	return string(r[:maxLastError]) + "…"
}

func (c *Controller) setErr(errs []error) {
	if len(errs) == 0 {
		c.health.LastError = ""
		return
	}
	full := errors.Join(errs...).Error()
	slog.Warn("webblock: apply incomplete", "err", full)
	c.health.LastError = clipError(full)
}

func (c *Controller) publish() {
	h := c.health
	c.published.Store(&h)
}

func (c *Controller) activate(l *List, force bool) {
	c.off = false
	var errs []error
	domains := l.Selected()
	sn := &snapshot{selected: make(map[string]bool, len(domains)), entries: l.Entries}
	for _, d := range domains {
		sn.selected[d] = true
	}
	c.snap.Store(sn)

	if force && c.caOK && !c.Authority.Installed() {
		// an admin removed the CA from the trust store, or its files are gone
		c.caOK = false
	}
	if !c.caOK {
		fp, err := c.Authority.Ensure(c.Hostname)
		if err != nil {
			errs = append(errs, fmt.Errorf("ca: %w", err))
			// never leave a half-installed CA; the page is still served over HTTP
			if rerr := c.Authority.Remove(); rerr != nil {
				errs = append(errs, fmt.Errorf("ca cleanup: %w", rerr))
			}
			c.ca, c.health.CAFingerprint = nil, ""
		} else {
			c.caOK, c.health.CAFingerprint = true, fp
			c.ca = nil
			if p, ok := c.Authority.(caProvider); ok {
				c.ca = p.CA()
			}
		}
	}
	if c.ca != nil {
		c.ca.SetAllowed(func(host string) bool {
			s := c.snap.Load()
			if s == nil {
				return false
			}
			_, ok := s.base(host)
			return ok
		})
	}

	page, contact := l.Policy.PageHTML, l.Policy.Contact
	swap := page != c.startPage || contact != c.startCont || c.ca != c.startCA
	// A failed start is retried when the list changed, or on the timer where
	// that is allowed (never on Linux, see retryStartOnTimer).
	retry := !c.started && (l.Version != c.startVer || (force && retryStartOnTimer))
	if !c.startTried || swap || retry {
		v6, status := c.Server.Start(page, contact, c.lookup, c.ca)
		c.ipv6, c.startPage, c.startCont, c.health.PageServer = v6, page, contact, status
		c.started = !strings.HasPrefix(status, "page_unavailable")
		c.startCA, c.startVer, c.startTried = c.ca, l.Version, true
	}

	bare := l.bareDomains(domains)
	var bareNames []string
	for _, d := range domains { // domains order is deterministic
		if bare[d] {
			bareNames = append(bareNames, d)
		}
	}
	key := strings.Join(domains, "\n") + fmt.Sprint("|", c.ipv6) + "|" + strings.Join(bareNames, "\n")
	if force || !c.hostsOK || key != c.hostsKey {
		recheck := force && c.hostsOK && key == c.hostsKey
		written, tampered, err := c.Hosts.Apply(domains, c.ipv6, bare)
		if recheck {
			// Nothing we wanted changed, so a rewrite repaired someone else's
			// edit (a deleted or edited block). A clean check clears it.
			c.health.HostsTampered = tampered || written
		} else {
			c.health.HostsTampered = tampered
		}
		c.hostsOK = err == nil
		if err != nil {
			errs = append(errs, fmt.Errorf("hosts: %w", err))
		} else {
			c.hostsKey = key
		}
	}

	c.health.CAInstalled = c.caOK && c.Authority.Installed()
	c.health.Enabled, c.health.Entries = true, len(domains)
	c.health.Version, c.health.Group = l.Version, l.Group
	c.setErr(errs)
}

func (c *Controller) lookup(host string) (Entry, bool) {
	s := c.snap.Load()
	if s == nil {
		return Entry{}, false
	}
	d, ok := s.base(host)
	if !ok {
		return Entry{}, false
	}
	return s.entries[d], true
}

// Health reports the state the last Apply left. It never waits for a
// running Apply.
func (c *Controller) Health() Health {
	if h := c.published.Load(); h != nil {
		return *h
	}
	return Health{}
}

// Run re-applies the store's list every 5 minutes until ctx ends: a tampered
// or removed hosts block is repaired and anything a previous Apply could not
// finish (trust store, a busy port) is retried.
func (c *Controller) Run(ctx context.Context, s *Store) {
	t := time.NewTicker(reapplyEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.applyCurrent(s.Current, true)
		}
	}
}

// Cleanup removes everything web protection put on the endpoint: the hosts
// block, the block page redirect (Linux), the CA from the trust store,
// <stateDir>/webblock (CA files and saved list) and the old
// <stateDir>/webblock.json. It needs no network and no running agent; an
// empty stateDir skips only the files. The error is non-nil only when the
// hosts block could not be removed; other failures are logged.
func Cleanup(stateDir string) error {
	if err := removeRedirects(); err != nil {
		slog.Warn("webblock: could not remove the block page redirect", "err", err)
	}
	return cleanup(stateDir, NewHostsFile(), &TrustStore{Dir: stateDir})
}

func cleanup(stateDir string, hosts Hosts, auth Authority) error {
	hostsErr := hosts.Remove()
	if hostsErr != nil {
		slog.Error("webblock: could not remove the hosts block", "err", hostsErr)
	}
	if err := auth.Remove(); err != nil {
		slog.Warn("webblock: could not remove the trust store entry", "err", err)
	}
	if stateDir == "" {
		return hostsErr
	}
	if err := os.RemoveAll(caDir(stateDir)); err != nil {
		slog.Warn("webblock: could not remove the CA files and saved list", "err", err)
	}
	legacy := filepath.Join(stateDir, LegacyListFile)
	tmps, _ := filepath.Glob(legacy + ".tmp*")
	for _, p := range append(tmps, legacy) {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			slog.Warn("webblock: could not remove the saved list", "path", p, "err", err)
		}
	}
	return hostsErr
}
