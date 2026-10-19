package firewall

import (
	"net"
	"testing"
)

func TestGuardProtectsLoopbackAndUnspecified(t *testing.T) {
	g := NewGuard("", nil)

	for _, cidr := range []string{"127.0.0.1", "127.5.5.5", "0.0.0.0", "127.0.0.0/8"} {
		r := Rule{Action: ActionBlock, CIDR: cidr, Direction: DirBoth}.normalize()
		if err := g.Protect(r); err == nil {
			t.Errorf("expected guard to block %s", cidr)
		}
	}
}

func TestGuardProtectsServerIP(t *testing.T) {
	g := NewGuard("https://203.0.113.10:8443/", nil)

	r := Rule{Action: ActionBlock, CIDR: "203.0.113.10", Direction: DirBoth}.normalize()
	if err := g.Protect(r); err == nil {
		t.Fatal("expected guard to refuse blocking the SIEM server")
	}

	neighbour := Rule{Action: ActionBlock, CIDR: "203.0.113.11", Direction: DirBoth}.normalize()
	if err := g.Protect(neighbour); err != nil {
		t.Fatalf("neighbouring IP should be blockable, got %v", err)
	}
}

func TestGuardProtectsExtraIPsAndCIDRs(t *testing.T) {
	g := NewGuard("", []string{"198.51.100.7", "10.20.0.0/16"})

	direct := Rule{Action: ActionBlock, CIDR: "198.51.100.7", Direction: DirBoth}.normalize()
	if err := g.Protect(direct); err == nil {
		t.Fatal("expected explicit protected IP to be refused")
	}

	inside := Rule{Action: ActionBlock, CIDR: "10.20.30.40", Direction: DirBoth}.normalize()
	if err := g.Protect(inside); err == nil {
		t.Fatal("expected address inside protected CIDR to be refused")
	}

	outside := Rule{Action: ActionBlock, CIDR: "10.21.0.1", Direction: DirBoth}.normalize()
	if err := g.Protect(outside); err != nil {
		t.Fatalf("address outside protected CIDR should pass, got %v", err)
	}
}

func TestGuardIgnoresAllowRules(t *testing.T) {
	g := NewGuard("https://203.0.113.10/", nil)
	r := Rule{Action: ActionAllow, CIDR: "203.0.113.10", Direction: DirBoth}.normalize()
	if err := g.Protect(r); err != nil {
		t.Fatalf("allow rules must never be rejected, got %v", err)
	}
}

func TestGuardCatchesCidrContainingServer(t *testing.T) {
	g := NewGuard("", []string{"192.168.50.10"})
	r := Rule{Action: ActionBlock, CIDR: "192.168.50.0/24", Direction: DirInbound}.normalize()
	if err := g.Protect(r); err == nil {
		t.Fatal("a /24 containing a protected address must be refused")
	}
}

func TestParseHexIPv4LE(t *testing.T) {
	cases := map[string]string{
		"0102A8C0": "192.168.2.1",
		"00000000": "0.0.0.0",
		"0A000001": "1.0.0.10",
	}
	for in, want := range cases {
		ip := parseHexIPv4LE(in)
		if ip == nil {
			t.Fatalf("%s: parse failed", in)
		}
		if ip.String() != want {
			t.Errorf("%s: got %s want %s", in, ip.String(), want)
		}
	}
	if parseHexIPv4LE("zz") != nil {
		t.Error("expected nil for malformed input")
	}
}

func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"https://siem.example.com:8443/api": "siem.example.com",
		"http://server-api:8000":            "server-api",
		"":                                  "",
		"not a url":                         "",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Errorf("hostFromURL(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHostNetMask(t *testing.T) {
	n := hostNet(net.ParseIP("203.0.113.5"))
	ones, bits := n.Mask.Size()
	if ones != 32 || bits != 32 {
		t.Fatalf("expected /32, got /%d of %d", ones, bits)
	}
}
