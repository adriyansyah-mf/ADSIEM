package dnssink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxDomains bounds the routed domains: NRPT and resolved routing domains
// are meant for a few hundred names, not a feed of tens of thousands (feeds
// stay in the hosts file).
const MaxDomains = 500

// reapplyEvery: systemd-resolved forgets runtime link settings when it restarts.
const reapplyEvery = 5 * time.Minute

// Controller keeps the resolver and the OS routing in step with the group
// policy (dns_sinkhole) and the web block's own domains.
type Controller struct {
	Router Router
	Push   func(logType, line string)
	Addr   string // resolver address (tests); default: what Router.Prepare returns

	mu       sync.Mutex
	srv      *Server
	on       bool
	domains  []string
	routed   string // key of the domains the OS routes
	lastLine string
}

// Apply turns the sinkhole on with these domains, or off.
func (c *Controller) Apply(on bool, domains []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := normalize(domains)
	c.on, c.domains = on, list
	c.reconcile(false)
}

// Refresh applies the routing again (a restarted systemd-resolved lost it).
func (c *Controller) Refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconcile(true)
}

// Run refreshes the routing every reapplyEvery until ctx ends, then takes
// everything away.
func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(reapplyEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Apply(false, nil)
			return
		case <-t.C:
			c.Refresh()
		}
	}
}

func normalize(domains []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" || !strings.Contains(d, ".") || seen[d] || strings.ContainsAny(d, " '\"\r\n\x00") {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) > MaxDomains {
		out = out[:MaxDomains]
	}
	return out
}

// reconcile: on with domains: resolver first, then routing (a name routed
// to a resolver that is not there would fail); off or no domains: routing
// first, then the resolver. c.mu held.
func (c *Controller) reconcile(force bool) {
	key := strings.Join(c.domains, ",")
	var err error
	if !c.on || len(c.domains) == 0 {
		if c.routed != "" || force {
			err = c.Router.Remove()
			if err == nil {
				c.routed = ""
			}
		}
		if c.srv != nil && c.routed == "" {
			c.srv.Close()
			c.srv = nil
		}
		c.state(err)
		return
	}
	if c.srv == nil {
		addr, err := c.Router.Prepare()
		if err != nil {
			c.state(err)
			return
		}
		if c.Addr != "" {
			addr = c.Addr
		}
		srv := &Server{Addr: addr, Push: c.Push}
		srv.Set(c.domains)
		if err := srv.Start(); err != nil {
			c.state(err)
			return
		}
		c.srv = srv
	}
	c.srv.Set(c.domains)
	if key != c.routed || force {
		if err = c.Router.Apply(c.domains); err == nil {
			c.routed = key
		}
	}
	c.state(err)
}

func (c *Controller) state(err error) {
	mode := "off"
	if c.on && len(c.domains) > 0 {
		mode = "on"
	}
	msg := ""
	if err != nil {
		msg = err.Error()
		if !errors.Is(err, ErrUnavailable) {
			slog.Warn("dnssink: not applied", "err", err)
		}
	}
	line := fmt.Sprintf("event=dns_sinkhole_state mode=%s domains=%d routed=%t error=%q",
		mode, len(c.domains), c.routed != "", msg)
	if line == c.lastLine || c.Push == nil {
		return
	}
	c.lastLine = line
	c.Push(LogType, line)
}
