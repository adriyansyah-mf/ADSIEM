package webblock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// reapplyEvery is how often Run re-checks the hosts block and retries
// whatever a previous Apply could not finish.
const reapplyEvery = 5 * time.Minute

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
	off       bool   // everything removed
	caOK      bool   // CA installed and handed to the server
	ca        *CA    // the CA Ensure installed
	startCA   *CA    // the CA the running server was started with
	started   bool   // Server.Start succeeded
	startPage string // page and contact the server runs with
	startCont string
	ipv6      bool   // [::1] listeners are up
	hostsOK   bool   // Hosts.Apply succeeded for hostsKey
	hostsKey  string // selected domains and ipv6 last written
	snap      atomic.Pointer[snapshot]
	health    Health
}

// Apply enforces l. It never panics; failures are recorded in Health.LastError.
func (c *Controller) Apply(l *List) { c.apply(l, false) }

// reapply is Apply that also rewrites the hosts block (a no-op on disk when
// the file is already right) so a tampered or removed block is repaired.
func (c *Controller) reapply(l *List) { c.apply(l, true) }

func (c *Controller) apply(l *List, force bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			c.health.LastError = fmt.Sprintf("web protection: %v", r)
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
	c.snap.Store(nil)
	c.health = Health{Version: l.Version, Group: l.Group}
	c.setErr(errs)
}

func (c *Controller) caFilesExist() bool {
	if c.StateDir == "" {
		return false
	}
	_, err := os.Stat(caDir(c.StateDir))
	return err == nil
}

func (c *Controller) setErr(errs []error) {
	if len(errs) == 0 {
		c.health.LastError = ""
		return
	}
	c.health.LastError = errors.Join(errs...).Error()
	slog.Warn("webblock: apply incomplete", "err", c.health.LastError)
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
	if !c.started || page != c.startPage || contact != c.startCont || c.ca != c.startCA {
		v6, status := c.Server.Start(page, contact, c.lookup, c.ca)
		c.ipv6, c.startPage, c.startCont, c.health.PageServer = v6, page, contact, status
		c.started = status == "ok"
		c.startCA = c.ca
	}

	key := strings.Join(domains, "\n") + fmt.Sprint("|", c.ipv6)
	if force || !c.hostsOK || key != c.hostsKey {
		tampered, err := c.Hosts.Apply(domains, c.ipv6)
		c.health.HostsTampered = tampered
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

// Health reports the state the last Apply left.
func (c *Controller) Health() Health {
	c.mu.Lock()
	h := c.health
	c.mu.Unlock()
	return h
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
			c.reapply(s.Current())
		}
	}
}

// Cleanup removes everything web protection put on the endpoint: the hosts
// block, the CA from the trust store, <stateDir>/webblock and the saved list.
// It needs no network and no running agent. The error is non-nil only when
// the hosts block could not be removed; other failures are logged.
func Cleanup(stateDir string) error {
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
	if err := os.RemoveAll(caDir(stateDir)); err != nil {
		slog.Warn("webblock: could not remove the CA files", "err", err)
	}
	list := filepath.Join(stateDir, ListFile)
	tmps, _ := filepath.Glob(list + ".tmp*")
	for _, p := range append(tmps, list) {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			slog.Warn("webblock: could not remove the saved list", "path", p, "err", err)
		}
	}
	return hostsErr
}
