package webblock

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type recorder struct {
	mu  sync.Mutex
	log []string
}

func (r *recorder) add(s string) { r.mu.Lock(); r.log = append(r.log, s); r.mu.Unlock() }
func (r *recorder) count(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.log {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

type fakeHosts struct {
	rec        *recorder
	applied    [][]string
	ipv6       []bool
	tampered   bool
	err, rmErr error
}

func (h *fakeHosts) Apply(d []string, v6 bool) (bool, error) {
	h.rec.add("hosts.apply")
	h.applied = append(h.applied, d)
	h.ipv6 = append(h.ipv6, v6)
	return h.tampered, h.err
}
func (h *fakeHosts) Remove() error { h.rec.add("hosts.remove"); return h.rmErr }

type fakeAuth struct {
	rec       *recorder
	ensureErr error
	ca        *CA
	installed bool

	countInstalled bool
	installedCalls int
}

func (a *fakeAuth) Ensure(string) (string, error) {
	a.rec.add("ca.ensure")
	if a.ensureErr != nil {
		return "", a.ensureErr
	}
	a.installed = true
	return "fp1", nil
}
func (a *fakeAuth) Remove() error { a.rec.add("ca.remove"); a.installed = false; return nil }
func (a *fakeAuth) Installed() bool {
	if a.countInstalled {
		a.installedCalls++
	}
	return a.installed
}
func (a *fakeAuth) CA() *CA {
	if a.installed {
		return a.ca
	}
	return nil
}

type startCall struct {
	page, contact string
	ca            *CA
	lookup        Lookup
}

type fakeServer struct {
	rec    *recorder
	starts []startCall
	ipv6   bool
	status string
}

func (s *fakeServer) Start(page, contact string, l Lookup, ca *CA) (bool, string) {
	s.rec.add("server.start")
	s.starts = append(s.starts, startCall{page, contact, ca, l})
	return s.ipv6, s.status
}
func (s *fakeServer) Stop() { s.rec.add("server.stop") }

func newCtl(t *testing.T) (*Controller, *fakeHosts, *fakeAuth, *fakeServer, *recorder) {
	t.Helper()
	rec := &recorder{}
	ca, err := generateCA("host")
	if err != nil {
		t.Fatal(err)
	}
	h, a, s := &fakeHosts{rec: rec}, &fakeAuth{rec: rec, ca: ca}, &fakeServer{rec: rec, ipv6: true, status: "ok"}
	return &Controller{Hosts: h, Authority: a, Server: s, Hostname: "host"}, h, a, s, rec
}

func listOf(version, page string, domains ...string) *List {
	l := Empty()
	l.Version, l.Group = version, "g"
	l.Policy = Policy{Enabled: true, PageHTML: page, Contact: "it@example.com"}
	for _, d := range domains {
		l.Entries[d] = Entry{Source: "manual", Reason: "r " + d}
	}
	return l
}

func TestApplyActive(t *testing.T) {
	c, h, a, s, rec := newCtl(t)
	l := listOf("g:1", "<p>x</p>", "evil.example", "bad.test")
	c.Apply(l)
	if !reflect.DeepEqual(rec.log, []string{"ca.ensure", "server.start", "hosts.apply"}) {
		t.Fatalf("order: %v", rec.log)
	}
	if !reflect.DeepEqual(h.applied[0], l.Selected()) || !h.ipv6[0] {
		t.Fatalf("hosts %v %v", h.applied, h.ipv6)
	}
	if s.starts[0].page != "<p>x</p>" || s.starts[0].contact != "it@example.com" || s.starts[0].ca != a.ca {
		t.Fatalf("start %+v", s.starts[0])
	}
	if e, ok := s.starts[0].lookup("www.evil.example"); !ok || e.Reason != "r evil.example" {
		t.Fatalf("lookup %v %v", e, ok)
	}
	if _, ok := s.starts[0].lookup("other.example"); ok {
		t.Fatal("unlisted host looked up")
	}
	hl := c.Health()
	if !hl.Enabled || hl.Entries != 2 || hl.Version != "g:1" || hl.Group != "g" || !hl.CAInstalled ||
		hl.CAFingerprint != "fp1" || hl.PageServer != "ok" || hl.LastError != "" {
		t.Fatalf("health %+v", hl)
	}
	// the CA only signs for listed domains
	if _, err := a.ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "www.evil.example"}); err != nil {
		t.Fatalf("listed: %v", err)
	}
	if _, err := a.ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Fatal("unlisted minted")
	}
}

func TestApplyIPv6OnlyWhenListenersUp(t *testing.T) {
	c, h, _, s, _ := newCtl(t)
	s.ipv6 = false
	c.Apply(listOf("g:1", "p", "evil.example"))
	if h.ipv6[0] {
		t.Fatal("ipv6 entries written without [::1] listeners")
	}
}

func TestApplyInactive(t *testing.T) {
	c, _, _, _, rec := newCtl(t)
	c.Apply(listOf("g:1", "p", "evil.example"))
	rec.log = nil
	c.Apply(Empty())
	if !reflect.DeepEqual(rec.log, []string{"hosts.remove", "server.stop", "ca.remove"}) {
		t.Fatalf("order: %v", rec.log)
	}
	if hl := c.Health(); hl.Enabled || hl.CAInstalled || hl.Entries != 0 {
		t.Fatalf("health %+v", hl)
	}
	// off again: nothing more to do
	rec.log = nil
	c.Apply(Empty())
	if len(rec.log) != 0 {
		t.Fatalf("repeat off: %v", rec.log)
	}
}

func TestApplyDisabledPolicyIsInactive(t *testing.T) {
	c, _, _, _, rec := newCtl(t)
	c.Authority.(*fakeAuth).installed = true
	l := listOf("g:1", "p", "evil.example")
	l.Policy.Enabled = false
	c.Apply(l)
	if !reflect.DeepEqual(rec.log, []string{"hosts.remove", "server.stop", "ca.remove"}) {
		t.Fatalf("%v", rec.log)
	}
}

func TestEnsureErrorKeepsBlocking(t *testing.T) {
	c, h, a, s, rec := newCtl(t)
	a.ensureErr = errors.New("no trust tool")
	c.Apply(listOf("g:1", "p", "evil.example"))
	if len(h.applied) != 1 || len(s.starts) != 1 {
		t.Fatalf("hosts %d starts %d", len(h.applied), len(s.starts))
	}
	if s.starts[0].ca != nil {
		t.Fatal("server given a CA that is not installed")
	}
	if rec.count("ca.remove") != 1 {
		t.Fatalf("half-installed CA not removed: %v", rec.log)
	}
	hl := c.Health()
	if !strings.Contains(hl.LastError, "no trust tool") || hl.CAInstalled || !hl.Enabled {
		t.Fatalf("health %+v", hl)
	}
}

func TestEnsureRetriedAfterFailure(t *testing.T) {
	c, _, a, s, _ := newCtl(t)
	a.ensureErr = errors.New("boom")
	l := listOf("g:1", "p", "evil.example")
	c.Apply(l)
	a.ensureErr = nil
	c.Apply(l)
	if len(s.starts) != 2 || s.starts[1].ca == nil {
		t.Fatalf("starts %+v", s.starts)
	}
	if c.Health().LastError != "" {
		t.Fatalf("error not cleared: %q", c.Health().LastError)
	}
}

func TestHostsTamperedAndError(t *testing.T) {
	c, h, _, _, _ := newCtl(t)
	h.tampered = true
	c.Apply(listOf("g:1", "p", "evil.example"))
	if !c.Health().HostsTampered {
		t.Fatal("tampered not reported")
	}
	c2, h2, _, _, _ := newCtl(t)
	h2.err = errors.New("read-only")
	c2.Apply(listOf("g:1", "p", "evil.example"))
	if hl := c2.Health(); !strings.Contains(hl.LastError, "read-only") {
		t.Fatalf("%+v", hl)
	}
}

func TestApplyIdempotent(t *testing.T) {
	c, _, _, _, rec := newCtl(t)
	c.Apply(listOf("g:1", "p", "evil.example"))
	c.Apply(listOf("g:1", "p", "evil.example"))
	if rec.count("ca.ensure") != 1 || rec.count("server.start") != 1 || rec.count("hosts.apply") != 1 {
		t.Fatalf("second apply did work: %v", rec.log)
	}
}

func TestApplyChangedDomains(t *testing.T) {
	c, h, a, s, rec := newCtl(t)
	c.Apply(listOf("g:1", "p", "evil.example"))
	c.Apply(listOf("g:2", "p", "evil.example", "new.example"))
	if rec.count("ca.ensure") != 1 || rec.count("server.start") != 1 || rec.count("hosts.apply") != 2 {
		t.Fatalf("log %v", rec.log)
	}
	if len(h.applied[1]) != 2 {
		t.Fatalf("%v", h.applied)
	}
	if _, err := a.ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "new.example"}); err != nil {
		t.Fatalf("allow set not updated: %v", err)
	}
	if e, ok := s.starts[0].lookup("new.example"); !ok || e.Source != "manual" {
		t.Fatal("running server's lookup not updated")
	}
	c.Apply(listOf("g:3", "p", "new.example"))
	if _, err := a.ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "evil.example"}); err == nil {
		t.Fatal("removed domain still minted")
	}
}

func TestApplyPageChangeSwaps(t *testing.T) {
	c, _, _, s, rec := newCtl(t)
	c.Apply(listOf("g:1", "p1", "evil.example"))
	c.Apply(listOf("g:2", "p2", "evil.example"))
	if rec.count("server.start") != 2 || rec.count("hosts.apply") != 1 || rec.count("ca.ensure") != 1 {
		t.Fatalf("log %v", rec.log)
	}
	if s.starts[1].page != "p2" {
		t.Fatal("page not swapped")
	}
}

func TestReapplyRepairsHostsOnly(t *testing.T) {
	c, h, _, _, rec := newCtl(t)
	l := listOf("g:1", "p", "evil.example")
	c.Apply(l)
	h.tampered = true
	c.reapply(l)
	if rec.count("hosts.apply") != 2 || rec.count("server.start") != 1 || rec.count("ca.ensure") != 1 {
		t.Fatalf("log %v", rec.log)
	}
	if !c.Health().HostsTampered {
		t.Fatal("tamper not reported")
	}
}

func TestPageUnavailableRetried(t *testing.T) {
	c, _, _, s, _ := newCtl(t)
	s.status = "page_unavailable: 127.84.0.1:80"
	l := listOf("g:1", "p", "evil.example")
	c.Apply(l)
	if c.Health().PageServer != s.status {
		t.Fatalf("%+v", c.Health())
	}
	s.status = "ok"
	c.Apply(l)
	if len(s.starts) != 2 || c.Health().PageServer != "ok" {
		t.Fatalf("starts %d %+v", len(s.starts), c.Health())
	}
}

func TestApplyNeverPanics(t *testing.T) {
	c := &Controller{}
	c.Apply(listOf("g:1", "p", "evil.example"))
	if c.Health().LastError == "" {
		t.Fatal("panic not recorded")
	}
}

func TestCleanup(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{}
	h, a := &fakeHosts{rec: rec}, &fakeAuth{rec: rec}
	cadir := filepath.Join(dir, CADirName)
	os.MkdirAll(cadir, 0o700)
	os.WriteFile(filepath.Join(cadir, CAKeyFile), []byte("k"), 0o600)
	list := filepath.Join(dir, ListFile)
	os.WriteFile(list, []byte("{}"), 0o600)
	if err := cleanup(dir, h, a); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cadir, list} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still there", p)
		}
	}
	if rec.count("hosts.remove") != 1 || rec.count("ca.remove") != 1 {
		t.Fatalf("%v", rec.log)
	}
}

func TestCleanupExitCodeOnlyForHosts(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{}
	h, a := &fakeHosts{rec: rec, rmErr: errors.New("locked")}, &fakeAuth{rec: rec}
	os.WriteFile(filepath.Join(dir, ListFile), []byte("{}"), 0o600)
	if err := cleanup(dir, h, a); err == nil {
		t.Fatal("hosts failure not reported")
	}
	// everything else was still attempted
	if _, err := os.Stat(filepath.Join(dir, ListFile)); !os.IsNotExist(err) {
		t.Fatal("list kept after hosts failure")
	}
	if rec.count("ca.remove") != 1 {
		t.Fatal("trust store skipped")
	}
}

func TestInactiveStartWithNothingToRemove(t *testing.T) {
	c, _, _, _, rec := newCtl(t)
	c.StateDir = t.TempDir()
	c.Apply(Empty())
	if rec.count("ca.remove") != 0 || c.Health().LastError != "" {
		t.Fatalf("log %v err %q", rec.log, c.Health().LastError)
	}
	// CA files left behind are removed
	os.MkdirAll(filepath.Join(c.StateDir, CADirName), 0o700)
	c2, _, _, _, rec2 := newCtl(t)
	c2.StateDir = c.StateDir
	c2.Apply(Empty())
	if rec2.count("ca.remove") != 1 {
		t.Fatalf("log %v", rec2.log)
	}
}

func TestHealthDoesNotQueryTrustStore(t *testing.T) {
	c, _, a, _, _ := newCtl(t)
	a.countInstalled = true
	c.Apply(listOf("g:1", "p", "evil.example"))
	n := a.installedCalls
	c.Health()
	c.Health()
	if a.installedCalls != n || !c.Health().CAInstalled {
		t.Fatalf("calls %d -> %d, health %+v", n, a.installedCalls, c.Health())
	}
}

func TestReapplyRepairsRemovedCA(t *testing.T) {
	c, _, a, s, rec := newCtl(t)
	l := listOf("g:1", "p", "evil.example")
	c.Apply(l)
	a.installed = false // admin removed it from the trust store
	ca2, err := generateCA("host")
	if err != nil {
		t.Fatal(err)
	}
	a.ca = ca2 // Ensure regenerates it
	c.reapply(l)
	if rec.count("ca.ensure") != 2 || len(s.starts) != 2 || s.starts[1].ca != ca2 {
		t.Fatalf("log %v starts %d", rec.log, len(s.starts))
	}
	if !c.Health().CAInstalled || c.Health().LastError != "" {
		t.Fatalf("%+v", c.Health())
	}
	// a plain Apply does not re-check
	a.installed = false
	c.Apply(l)
	if rec.count("ca.ensure") != 2 {
		t.Fatalf("Apply re-ensured: %v", rec.log)
	}
}

func TestReapplyCARepairFailureRecorded(t *testing.T) {
	c, _, a, _, _ := newCtl(t)
	l := listOf("g:1", "p", "evil.example")
	c.Apply(l)
	a.installed = false
	a.ensureErr = errors.New("denied")
	c.reapply(l)
	if h := c.Health(); !strings.Contains(h.LastError, "denied") || h.CAInstalled {
		t.Fatalf("%+v", h)
	}
}
