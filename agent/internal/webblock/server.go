package webblock

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
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
	// both [::1] listeners are up; status is "ok" or names the failed binds.
	Start(page, contact string, lookup Lookup, ca *CA) (ipv6 bool, status string)
	Stop()
}

// Addrs are the four listen addresses; an all-empty value means the defaults,
// otherwise an empty field is not started (tests use ephemeral ports).
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

	mu      sync.RWMutex
	page    string
	contact string
	lookup  Lookup
	ca      *CA

	lmu       sync.Mutex // guards the fields below
	listeners map[string]*listener
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
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	domain := hostOf(r.Host)
	if len(domain) > maxLoggedDomain {
		domain = domain[:maxLoggedDomain]
	}
	s.mu.RLock()
	page, contact, lookup := s.page, s.contact, s.lookup
	s.mu.RUnlock()
	entry := Entry{Source: fallbackSource, Reason: fallbackReason}
	if lookup != nil {
		if e, ok := lookup(domain); ok {
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
	w.WriteHeader(http.StatusForbidden)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	s.emit(r, domain, entry)
}

func (s *Server) emit(r *http.Request, domain string, entry Entry) {
	if s.Push == nil {
		return
	}
	pid, name := clientProcess(r.RemoteAddr)
	emit, suppressed := s.limiter.Allow(domain, pid, s.now())
	if !emit {
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	path := r.URL.Path
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath]
	}
	s.Push(LogType, Event{Domain: domain, Scheme: scheme, Path: path, Source: entry.Source,
		Reason: entry.Reason, Process: name, PID: pid, Count: 1 + suppressed}.Line())
}

func (s *Server) addrs() Addrs {
	if s.Addrs == (Addrs{}) {
		return Addrs{AddrHTTP4, AddrHTTPS4, AddrHTTP6, AddrHTTPS6}
	}
	return s.Addrs
}

// Start implements PageServer. Each listener binds independently.
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
	a := s.addrs()
	var failed []string
	up := map[string]bool{}
	for _, spec := range []struct {
		name, addr string
		tls        bool
	}{
		{"http4", a.HTTP4, false}, {"https4", a.HTTPS4, true},
		{"http6", a.HTTP6, false}, {"https6", a.HTTPS6, true},
	} {
		if spec.addr == "" {
			continue
		}
		if _, ok := s.listeners[spec.name]; ok && (!spec.tls || ca != nil) {
			up[spec.name] = true
			continue
		}
		if spec.tls && ca == nil {
			failed = append(failed, spec.addr+" (no CA)")
			continue
		}
		ln, err := net.Listen("tcp", spec.addr)
		if err != nil {
			failed = append(failed, spec.addr)
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
	ipv6 := up["http6"] && up["https6"]
	if len(failed) == 0 {
		return ipv6, "ok"
	}
	return ipv6, "page_unavailable: " + strings.Join(failed, ", ")
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

// Stop closes every listener; calling it again is harmless.
func (s *Server) Stop() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
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
