//go:build windows

package firewall

import (
	"net"
	"testing"
	"time"
)

// On a real (elevated) Windows host, WFP filters from SetIOCs block new
// connections to the address and closing the list restores them. Needs
// outbound internet (the windows-agent workflow runner has it).
func TestWFPBlocksAndReleasesAnAddress(t *testing.T) {
	setter := newPlatformIOC()
	if setter == nil {
		t.Fatal("fwpuclnt.dll has no FwpmEngineOpen0/FwpmFilterAdd0")
	}
	const target = "1.1.1.1:443"
	dial := func() error {
		c, err := net.DialTimeout("tcp", target, 4*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial(); err != nil {
		t.Skipf("no baseline connectivity to %s: %v", target, err)
	}
	t.Cleanup(func() { _ = setter.SetIOCs(nil, nil) })

	if err := setter.SetIOCs([]string{"1.1.1.0/24"}, []string{"2606:4700:4700::/48"}); err != nil {
		t.Fatalf("SetIOCs: %v", err)
	}
	if err := dial(); err == nil {
		t.Fatal("a connection to a listed address must be blocked")
	}

	// a change replaces the session: the old filters go with it
	if err := setter.SetIOCs([]string{"192.0.2.1/32"}, nil); err != nil {
		t.Fatalf("SetIOCs replace: %v", err)
	}
	if err := dial(); err != nil {
		t.Fatalf("an address dropped from the list must be reachable again: %v", err)
	}
	if err := setter.SetIOCs(nil, nil); err != nil {
		t.Fatalf("SetIOCs clear: %v", err)
	}
}
