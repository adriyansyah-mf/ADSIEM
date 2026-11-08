//go:build windows

package webblock

import (
	"net"
	"strconv"
	"testing"
)

// TestWindowsWildcardBindAfterSink documents why Windows needs no redirect:
// after the page server binds a specific loopback address on a port, another
// program can still bind the wildcard address on the same port (unlike
// Linux, where that fails with EADDRINUSE). If this assumption breaks, CI
// says so here.
func TestWindowsWildcardBindAfterSink(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	s := &Server{Addrs: Addrs{HTTP4: net.JoinHostPort(SinkV4, strconv.Itoa(port))}}
	if _, status := s.Start(testPage, "", testLookup, nil); status != "ok" {
		t.Fatalf("page server on %s:%d: %s", SinkV4, port, status)
	}
	defer s.Stop()

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("wildcard bind of port %d after the sink bind failed: %v", port, err)
	}
	ln.Close()
}
