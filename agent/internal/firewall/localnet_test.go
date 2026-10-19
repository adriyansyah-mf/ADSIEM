package firewall

import (
	"net"
	"testing"
)

func TestLocalNetForCoversSameSubnet(t *testing.T) {
	n := localNetFor(net.ParseIP("127.0.0.1"))
	if n == nil {
		t.Skip("loopback has no separate on-link subnet here")
	}
	if !n.Contains(net.ParseIP("127.0.0.2")) {
		t.Fatalf("expected the on-link subnet to contain siblings, got %s", n)
	}
}

func TestLocalNetForRejectsPublicIP(t *testing.T) {
	if n := localNetFor(net.ParseIP("203.0.113.99")); n != nil {
		t.Fatalf("a public address is not on-link, got %s", n)
	}
}

func TestLocalNetForHandlesNil(t *testing.T) {
	if n := localNetFor(nil); n != nil {
		t.Fatal("nil ip must yield nil")
	}
}
