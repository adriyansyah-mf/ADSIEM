//go:build linux

package webblock

import (
	"net"
	"testing"
)

// In fallback mode our own listener holds the sink ports, so the port check
// must not run for a listener that is already up: a second Start (page
// change) stays "ok" and does not rebind.
func TestFallbackSecondStartDoesNotSeeOwnListener(t *testing.T) {
	old := portInUse
	t.Cleanup(func() { portInUse = old })
	portInUse = func(int) bool { return true } // as if our own listeners held 80/443
	s := &Server{}
	s.detectOnce.Do(func() {}) // no redirect backend
	t.Cleanup(s.Stop)
	s.listeners = map[string]*listener{}
	for _, n := range []string{"http4", "https4"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := s.newHTTPServer()
		go func() { _ = srv.Serve(ln) }()
		s.listeners[n] = &listener{addr: ln.Addr().String(), ln: ln, srv: srv}
	}
	before := s.Bound()
	for i := 0; i < 2; i++ {
		if _, status := s.Start(testPage, "", testLookup, testCA(t)); status != "ok" {
			t.Fatalf("start %d: %q", i, status)
		}
	}
	if s.Bound() != before {
		t.Fatalf("rebound: %+v -> %+v", before, s.Bound())
	}
}

// Detecting the backend first removes both backends' rules by name, so a
// backend change between runs leaves no stale rules.
func TestDetectAndCleanRemovesBothBackends(t *testing.T) {
	old := redirectLookPath
	t.Cleanup(func() { redirectLookPath = old })
	redirectLookPath = func(n string) (string, error) { return "/sbin/" + n, nil }
	// no iptables chain exists: -S fails
	calls := fakeCmds(t, func(a []string) bool { return len(a) > 4 && a[3] == "-S" && a[4] == iptChain })
	r := detectAndClean()
	if _, ok := r.(nftRedirect); !ok {
		t.Fatalf("backend %T", r)
	}
	var nftRemoved, iptChecked bool
	for _, c := range *calls {
		if c.path == "/sbin/nft" && c.stdin == nftRemoveScript() {
			nftRemoved = true
		}
		if c.path == "/sbin/iptables" && len(c.args) > 4 && c.args[3] == "-S" && c.args[4] == iptChain {
			iptChecked = true
		}
	}
	if !nftRemoved || !iptChecked {
		t.Fatalf("nft removed %v, iptables chain checked %v: %v", nftRemoved, iptChecked, argLists(*calls))
	}
}
