package dnssink

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func query(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b
}

type reply struct {
	id     uint16
	rcode  int
	answer int
	ip     net.IP
}

func parseReply(t *testing.T, b []byte) reply {
	t.Helper()
	if len(b) < 12 || b[2]&0x80 == 0 {
		t.Fatalf("not a response: %x", b)
	}
	r := reply{id: binary.BigEndian.Uint16(b[0:2]), rcode: int(b[3] & 0x0f), answer: int(binary.BigEndian.Uint16(b[6:8]))}
	if r.answer == 1 {
		r.ip = net.IP(b[len(b)-4:])
	}
	return r
}

var blocked = Matcher{"evil.com": true, "phish.example.org": true}

func TestBlockedNamesAndEverySubdomainGetTheSink(t *testing.T) {
	for _, name := range []string{"evil.com", "cdn.evil.com", "a.b.c.EVIL.com", "login.phish.example.org"} {
		out, ans := Handle(query(7, name, typeA), blocked.Under)
		r := parseReply(t, out)
		if r.id != 7 || r.rcode != rcodeNoError || r.answer != 1 || !r.ip.Equal(net.IPv4(127, 84, 0, 1)) || ans.Blocked == "" {
			t.Fatalf("%s: %+v %+v", name, r, ans)
		}
	}
	// AAAA and other types: an empty answer (the page is IPv4)
	for _, qt := range []uint16{typeAAAA, 15, 16} {
		out, _ := Handle(query(8, "x.evil.com", qt), blocked.Under)
		if r := parseReply(t, out); r.rcode != rcodeNoError || r.answer != 0 {
			t.Fatalf("type %d: %+v", qt, r)
		}
	}
}

func TestOtherNamesAreRefused(t *testing.T) {
	for _, name := range []string{"notevil.com", "evil.com.attacker.net", "example.org", "com"} {
		out, ans := Handle(query(9, name, typeA), blocked.Under)
		if r := parseReply(t, out); r.rcode != rcodeRefused || r.answer != 0 || ans.Blocked != "" {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

func TestMalformedQueries(t *testing.T) {
	if out, _ := Handle([]byte{1, 2, 3}, blocked.Under); out != nil {
		t.Fatal("too short: no answer")
	}
	resp := query(1, "evil.com", typeA)
	resp[2] |= 0x80
	if out, _ := Handle(resp, blocked.Under); out != nil {
		t.Fatal("a response is never answered")
	}
	comp := query(2, "evil.com", typeA)
	comp[12] = 0xC0
	if out, _ := Handle(comp, blocked.Under); parseReply(t, out).rcode != rcodeFormErr {
		t.Fatal("compression in a question: FORMERR")
	}
	base := query(3, "deep.sub.evil.com", typeA)
	buf := make([]byte, len(base))
	for i := 0; i < 5000; i++ {
		copy(buf, base)
		for j := 0; j < 4; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(buf))))
			v, _ := rand.Int(rand.Reader, big.NewInt(256))
			buf[n.Int64()] = byte(v.Int64())
		}
		_, _ = Handle(buf, blocked.Under)
	}
}

func TestServerAnswersOverUDPAndTCP(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	s := &Server{Addr: "127.0.0.1:0", Push: func(_, l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }}
	s.Set([]string{"Evil.com."})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("udp", s.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(query(11, "track.evil.com", typeA))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil || !parseReply(t, buf[:n]).ip.Equal(net.IPv4(127, 84, 0, 1)) {
		t.Fatalf("udp: %v %x", err, buf[:n])
	}
	c.Close()

	tc, err := net.Dial("tcp", s.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	q := query(12, "evil.com", typeA)
	tc.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...))
	var l [2]byte
	if _, err := io.ReadFull(tc, l[:]); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	io.ReadFull(tc, msg)
	if r := parseReply(t, msg); r.id != 12 || r.answer != 1 {
		t.Fatalf("tcp: %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 || !strings.Contains(lines[0], `blocked="evil.com"`) {
		t.Fatalf("lines: %v", lines)
	}
}

type recorder struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool
}

func (r *recorder) exec(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.calls = append(r.calls, c)
	for k := range r.fail {
		if strings.HasPrefix(c, k) {
			return "", errors.New("exit status 1")
		}
	}
	return "", nil
}

func (r *recorder) has(c string) bool {
	for _, x := range r.calls {
		if x == c {
			return true
		}
	}
	return false
}

func TestResolvedRouterCommands(t *testing.T) {
	rec := &recorder{fail: map[string]bool{"ip link show": true}}
	r := ResolvedRouter{Run: rec.exec}
	if err := r.Apply([]string{"phish.example.org", "evil.com"}); err != nil {
		t.Fatal(err)
	}
	if addr, err := r.Prepare(); err != nil || addr != "169.254.84.1:53" {
		t.Fatalf("prepare: %q %v", addr, err)
	}
	for _, want := range []string{"ip link add adsiem-dns type dummy", "ip link set adsiem-dns up",
		"ip addr replace 169.254.84.1/32 dev adsiem-dns", "resolvectl dns adsiem-dns 169.254.84.1",
		"resolvectl domain adsiem-dns ~evil.com ~phish.example.org", "resolvectl default-route adsiem-dns false"} {
		if !rec.has(want) {
			t.Fatalf("missing %q in %v", want, rec.calls)
		}
	}
	none := &recorder{fail: map[string]bool{"systemctl is-active": true}}
	if err := (ResolvedRouter{Run: none.exec}).Apply([]string{"evil.com"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("without systemd-resolved: %v", err)
	}
	rm := &recorder{}
	(ResolvedRouter{Run: rm.exec}).Remove()
	if !rm.has("ip link del adsiem-dns") {
		t.Fatalf("remove: %v", rm.calls)
	}
}

func TestNRPTScriptTouchesOnlyItsOwnRule(t *testing.T) {
	s := NRPTScript([]string{"evil.com", "o'brien.com"})
	for _, want := range []string{"$c = 'ADSIEM DNS sinkhole'", "Where-Object { $_.Comment -eq $c }",
		"$ns = @('evil.com', '.evil.com', 'o''brien.com', '.o''brien.com')",
		"Add-DnsClientNrptRule -Namespace $ns -NameServers '127.84.0.1' -Comment $c", "Clear-DnsClientCache"} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(NRPTScript(nil), "Add-DnsClientNrptRule") {
		t.Fatal("no domains: only the removal")
	}
}

type fakeRouter struct {
	applied [][]string
	removed int
	err     error
}

func (f *fakeRouter) Apply(d []string) error {
	f.applied = append(f.applied, append([]string(nil), d...))
	return f.err
}
func (f *fakeRouter) Remove() error            { f.removed++; return nil }
func (f *fakeRouter) Prepare() (string, error) { return "127.0.0.1:0", nil }

func TestControllerOrdersResolverAndRouting(t *testing.T) {
	fr := &fakeRouter{}
	var lines []string
	c := &Controller{Router: fr, Addr: "127.0.0.1:0", Push: func(_, l string) { lines = append(lines, l) }}
	c.Apply(true, []string{"Evil.com", "evil.com", "bad domain", "phish.example.org"})
	if c.srv == nil || len(fr.applied) != 1 || strings.Join(fr.applied[0], ",") != "evil.com,phish.example.org" {
		t.Fatalf("on: srv=%v applied=%v", c.srv != nil, fr.applied)
	}
	c.Apply(true, []string{"phish.example.org", "evil.com"})
	if len(fr.applied) != 1 {
		t.Fatal("unchanged domains are not routed again")
	}
	c.Refresh()
	if len(fr.applied) != 2 {
		t.Fatal("refresh routes again")
	}
	c.Apply(false, nil)
	if fr.removed == 0 || c.srv != nil {
		t.Fatalf("off: removed=%d srv=%v", fr.removed, c.srv != nil)
	}
	if !strings.Contains(lines[0], "mode=on domains=2 routed=true") || !strings.Contains(lines[len(lines)-1], "mode=off") {
		t.Fatalf("lines: %v", lines)
	}

	// the resolver cannot bind: nothing is routed to it
	fr2 := &fakeRouter{}
	c2 := &Controller{Router: fr2, Addr: "256.0.0.1:53"}
	c2.Apply(true, []string{"evil.com"})
	if len(fr2.applied) != 0 || c2.srv != nil {
		t.Fatal("no resolver, no routing")
	}
}

type persistentRouter struct{ *fakeRouter }

func (persistentRouter) Persistent() bool { return true }

// NRPT keeps its rule: the periodic refresh must not run PowerShell again
// (each run was a Sigma encoded-command alert), on or off, unless the last
// apply failed.
func TestRefreshLeavesPersistentRoutingAlone(t *testing.T) {
	fr := &fakeRouter{}
	c := &Controller{Router: persistentRouter{fr}, Addr: "127.0.0.1:0"}
	defer c.Apply(false, nil)

	c.Refresh() // sinkhole off, nothing routed
	if fr.removed != 0 || len(fr.applied) != 0 {
		t.Fatalf("off refresh: removed=%d applied=%d", fr.removed, len(fr.applied))
	}
	c.Apply(true, []string{"evil.com"})
	c.Refresh()
	c.Refresh()
	if len(fr.applied) != 1 {
		t.Fatalf("on refresh re-applied: %d applies", len(fr.applied))
	}

	fr.err = errors.New("powershell failed")
	c.Apply(true, []string{"evil.com", "phish.example.org"})
	fr.err = nil
	c.Refresh() // the failed apply is retried
	if len(fr.applied) != 3 || strings.Join(fr.applied[2], ",") != "evil.com,phish.example.org" {
		t.Fatalf("failed apply not retried: %v", fr.applied)
	}
	c.Refresh()
	if len(fr.applied) != 3 {
		t.Fatalf("retried apply re-applied again: %d", len(fr.applied))
	}
}

func TestNRPTRouterIsPersistent(t *testing.T) {
	var r Router = NRPTRouter{}
	if p, ok := r.(persistent); !ok || !p.Persistent() {
		t.Fatal("NRPT routing must not be rewritten by every refresh")
	}
}
