package dnssink

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LogType of the lines the resolver emits (decoders/dns_sinkhole.yaml).
const LogType = "dns_sinkhole"

// Addr is where the resolver listens: the web block's sink address.
const Addr = "127.84.0.1:53"

// Server is the resolver. Set swaps the blocked domains at any time.
type Server struct {
	Addr string // default Addr
	Push func(logType, line string)

	set   atomic.Pointer[Matcher]
	udp   net.PacketConn
	tcp   net.Listener
	once  sync.Once
	stop  chan struct{}
	mu    sync.Mutex
	seen  map[string]int64 // name -> last report (unix seconds), at most maxSeen
	count atomic.Uint64
}

// Set replaces the blocked domains (lower case, no trailing dot).
func (s *Server) Set(domains []string) {
	m := Matcher{}
	for _, d := range domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" {
			m[d] = true
		}
	}
	s.set.Store(&m)
}

func (s *Server) under(name string) string {
	m := s.set.Load()
	if m == nil {
		return ""
	}
	return m.Under(name)
}

// Start listens on UDP and TCP. It fails when the address cannot be bound
// (another DNS server there, no privilege for port 53).
func (s *Server) Start() error {
	addr := s.Addr
	if addr == "" {
		addr = Addr
	}
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dnssink: listen udp %s: %w", addr, err)
	}
	// same port as UDP (matters when addr asks for port 0)
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		return fmt.Errorf("dnssink: listen tcp %s: %w", addr, err)
	}
	s.udp, s.tcp, s.stop = udp, tcp, make(chan struct{})
	go s.serveUDP()
	go s.serveTCP()
	return nil
}

// LocalAddr is the UDP address it listens on (tests use port 0).
func (s *Server) LocalAddr() string { return s.udp.LocalAddr().String() }

// Close stops both listeners.
func (s *Server) Close() {
	s.once.Do(func() {
		if s.stop != nil {
			close(s.stop)
		}
		if s.udp != nil {
			s.udp.Close()
		}
		if s.tcp != nil {
			s.tcp.Close()
		}
	})
}

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		out, ans := Handle(buf[:n], s.under)
		s.report(ans)
		if out != nil {
			_, _ = s.udp.WriteTo(out, from)
		}
	}
}

func (s *Server) serveTCP() {
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(c)
	}
}

func (s *Server) handleTCP(c net.Conn) {
	defer c.Close()
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n == 0 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		out, ans := Handle(msg, s.under)
		if out == nil {
			return
		}
		s.report(ans)
		binary.BigEndian.PutUint16(l[:], uint16(len(out)))
		if _, err := c.Write(append(l[:], out...)); err != nil {
			return
		}
	}
}

// report pushes one line per sinkholed name a minute at most: who asked is
// not known to a DNS server (the process shows up in the DNS sensor lines).
func (s *Server) report(a Answer) {
	if a.Blocked == "" || s.Push == nil {
		return
	}
	s.count.Add(1)
	now := time.Now().Unix()
	s.mu.Lock()
	if last, ok := s.seen[a.Name]; ok && now-last < 60 {
		s.mu.Unlock()
		return
	}
	if s.seen == nil || len(s.seen) >= maxSeen { // random subdomains must not grow it without end
		s.seen = map[string]int64{}
	}
	s.seen[a.Name] = now
	s.mu.Unlock()
	s.Push(LogType, fmt.Sprintf("event=dns_sinkhole name=%q qtype=%d blocked=%q", a.Name, a.Type, a.Blocked))
}

const maxSeen = 4096

// Answered is how many queries for blocked names it answered since start.
func (s *Server) Answered() uint64 { return s.count.Load() }

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) {
	<-ctx.Done()
	s.Close()
	slog.Info("dnssink: stopped")
}
