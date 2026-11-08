package webblock

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Listen addresses of the block page server.
const (
	AddrHTTP4  = SinkV4 + ":80"
	AddrHTTPS4 = SinkV4 + ":443"
	AddrHTTP6  = "[::1]:80"
	AddrHTTPS6 = "[::1]:443"
)

const (
	cspValue        = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'"
	fallbackReason  = "Blocked by your organisation"
	fallbackSource  = "policy"
	maxLoggedDomain = 253
	maxLoggedPath   = 200
)

// Lookup returns the listed entry for a host (www. falls back to the apex).
type Lookup func(host string) (Entry, bool)

// PageServer serves the block page for blocked domains.
type PageServer interface {
	// Start serves the page (or swaps it when already running). ipv6 says
	// both [::1] listeners are up; status is "ok", "ok (ipv4 only)" (no IPv6
	// on the host) or "page_unavailable: ..." naming the failed binds.
	Start(page, contact string, lookup Lookup, ca *CA) (ipv6 bool, status string)
	Stop()
}

// Addrs are the four listen addresses; an all-empty value means the platform
// defaults (Linux: high ports on 127.0.0.1 behind a redirect, no [::1];
// elsewhere the four sink addresses), otherwise an empty field is not started
// (tests use ephemeral ports).
type Addrs struct{ HTTP4, HTTPS4, HTTP6, HTTPS6 string }

type listener struct {
	addr string
	ln   net.Listener
	srv  *http.Server
}

// Server is the local block page server. It only ever answers with the page.
type Server struct {
	Push     func(logType, line string)
	Hostname string
	Addrs    Addrs
	Now      func() time.Time // tests

	limiter Limiter
	// lookupSlot lets one process lookup run at a time; a busy request skips it.
	lookupOnce sync.Once
	lookupSlot chan struct{}
	findProc   func(remoteAddr string) (int, string) // tests; default clientProcess

	mu      sync.RWMutex
	page    string
	contact string
	lookup  Lookup
	ca      *CA

	lmu       sync.Mutex // guards the fields below
	listeners map[string]*listener
	redirect  Redirector // applied by Start, removed by Stop

	// Redirect overrides the detected redirect backend (tests). Only the
	// default addresses on Linux use one.
	Redirect   Redirector
	detectOnce sync.Once
	detected   Redirector
}

var _ PageServer = (*Server)(nil)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) set(page, contact string, lookup Lookup) {
	s.mu.Lock()
	s.page, s.contact, s.lookup = page, contact, lookup
	s.mu.Unlock()
}

// hostOf extracts the lowercase host from a Host header value.
func hostOf(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func (s *Server) newHTTPServer() *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	domain := hostOf(r.Host)
	domain = truncRunes(domain, maxLoggedDomain)
	s.mu.RLock()
	page, contact, lookup := s.page, s.contact, s.lookup
	s.mu.RUnlock()
	entry := Entry{Source: fallbackSource, Reason: fallbackReason}
	listed := false
	if lookup != nil {
		if e, ok := lookup(domain); ok {
			listed = true
			if e.Reason != "" {
				entry.Reason = e.Reason
			}
			if e.Source != "" {
				entry.Source = e.Source
			}
		}
	}
	body := Document(page, map[string]string{
		"domain":   domain,
		"reason":   entry.Reason,
		"source":   entry.Source,
		"time":     s.now().UTC().Format("2006-01-02 15:04 UTC"),
		"hostname": s.Hostname,
		"contact":  contact,
	})
	h := w.Header()
	h.Set("Content-Security-Policy", cspValue)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush() // the client has the page before the process lookup runs
	}
	// Any local process can send any Host header; only a listed domain is a
	// block worth reporting.
	if listed {
		s.emit(r, domain, entry)
	}
}

// process looks the client up, one lookup at a time; when one is running the
// request goes without process details.
func (s *Server) process(remoteAddr string) (int, string) {
	s.lookupOnce.Do(func() { s.lookupSlot = make(chan struct{}, 1) })
	select {
	case s.lookupSlot <- struct{}{}:
		defer func() { <-s.lookupSlot }()
	default:
		return 0, ""
	}
	if s.findProc != nil {
		return s.findProc(remoteAddr)
	}
	return clientProcess(remoteAddr)
}

func (s *Server) emit(r *http.Request, domain string, entry Entry) {
	if s.Push == nil {
		return
	}
	pid, name := s.process(r.RemoteAddr)
	emit, suppressed := s.limiter.Allow(domain, pid, s.now())
	if !emit {
		return
	}
	// HTTPS carries the host only: the path was encrypted for the real site.
	scheme, path := "https", ""
	if r.TLS == nil {
		scheme, path = "http", truncRunes(r.URL.Path, maxLoggedPath)
	}
	s.Push(LogType, Event{Domain: domain, Scheme: scheme, Path: path, Source: entry.Source,
		Reason: entry.Reason, Process: name, PID: pid, Count: 1 + suppressed}.Line())
}

// Redirector sends the sink's ports 80/443 to the page server's listeners
// (Linux: nft or iptables NAT OUTPUT). A zero port has no rule.
type Redirector interface {
	Apply(httpPort, httpsPort int) error
	Remove() error
}

// bindSpec is one listener of a start plan.
type bindSpec struct {
	name, addr string
	label      string // address reported in the status (the sink address when redirected)
	tls        bool
	v6         bool   // an IPv6 listener: an unavailable stack is not a failure
	redirect   int    // the sink port redirected to this listener (0: none)
	skip       string // reason not to bind at all
}

func (s *Server) plan() ([]bindSpec, Redirector) {
	if s.Addrs == (Addrs{}) {
		return s.defaultPlan()
	}
	a := s.Addrs
	var specs []bindSpec
	for _, sp := range []bindSpec{
		{name: "http4", addr: a.HTTP4}, {name: "https4", addr: a.HTTPS4, tls: true},
		{name: "http6", addr: a.HTTP6, v6: true}, {name: "https6", addr: a.HTTPS6, tls: true, v6: true},
	} {
		if sp.addr != "" {
			sp.label = sp.addr
			specs = append(specs, sp)
		}
	}
	return specs, nil
}

// noIPv6 reports a bind error that means the host has no usable IPv6.
func noIPv6(err error) bool {
	if errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) {
		return true
	}
	for _, e := range platformNoIPv6 {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func listenPort(l *listener) int {
	if l == nil {
		return 0
	}
	if a, ok := l.ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// Start implements PageServer. Each listener binds independently; with a
// redirect the rules are (re)applied for the current listener ports.
func (s *Server) Start(page, contact string, lookup Lookup, ca *CA) (bool, string) {
	s.set(page, contact, lookup)
	s.mu.Lock()
	s.ca = ca
	s.mu.Unlock()
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.listeners == nil {
		s.listeners = map[string]*listener{}
	}
	specs, red := s.plan()
	var failed []string
	v6missing := false
	up := map[string]bool{}
	for _, spec := range specs {
		if _, ok := s.listeners[spec.name]; ok && (!spec.tls || ca != nil) {
			up[spec.name] = true
			continue
		}
		if spec.skip != "" {
			failed = append(failed, spec.label+" ("+spec.skip+")")
			continue
		}
		if spec.tls && ca == nil {
			failed = append(failed, spec.label+" (no CA)")
			continue
		}
		ln, err := net.Listen("tcp", spec.addr)
		if err != nil {
			if spec.v6 && noIPv6(err) {
				v6missing = true
				continue
			}
			failed = append(failed, spec.label)
			continue
		}
		srv := s.newHTTPServer()
		serveLn := ln
		if spec.tls {
			serveLn = tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.getCertificate})
		}
		s.listeners[spec.name] = &listener{addr: ln.Addr().String(), ln: ln, srv: srv}
		up[spec.name] = true
		go func() { _ = srv.Serve(serveLn) }()
	}
	if red != nil {
		hp, sp := listenPort(s.listeners["http4"]), listenPort(s.listeners["https4"])
		if err := red.Apply(hp, sp); err != nil {
			slog.Warn("webblock: could not install the block page redirect", "err", err)
			failed = append(failed, "redirect ("+truncRunes(err.Error(), 120)+")")
		}
		s.redirect = red
	}
	ipv6 := up["http6"] && up["https6"]
	switch {
	case len(failed) > 0:
		return ipv6, "page_unavailable: " + strings.Join(failed, ", ")
	case v6missing:
		return false, "ok (ipv4 only)"
	}
	return ipv6, "ok"
}

// Bound returns the addresses actually listening (empty when not).
func (s *Server) Bound() Addrs {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	get := func(n string) string {
		if l := s.listeners[n]; l != nil {
			return l.addr
		}
		return ""
	}
	return Addrs{get("http4"), get("https4"), get("http6"), get("https6")}
}

// Stop removes the redirect and closes every listener; calling it again is
// harmless.
func (s *Server) Stop() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.redirect != nil {
		if err := s.redirect.Remove(); err != nil {
			slog.Warn("webblock: could not remove the block page redirect", "err", err)
		}
		s.redirect = nil
	}
	for name, l := range s.listeners {
		_ = l.srv.Close()
		_ = l.ln.Close()
		delete(s.listeners, name)
	}
}

// getCertificate defers to the current CA, so a restart with a new CA needs no rebind.
func (s *Server) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	ca := s.ca
	s.mu.RUnlock()
	if ca == nil {
		return nil, errNoCA
	}
	return ca.GetCertificate(h)
}

var errNoCA = errors.New("webblock: no CA")
