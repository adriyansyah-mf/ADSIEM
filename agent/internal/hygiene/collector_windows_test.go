//go:build windows

package hygiene

import "testing"

// The real collector on a Windows runner: posture, ports with their owner
// and the network identity, without panicking.
func TestCollectOnWindows(t *testing.T) {
	r, err := Collect("a", "h")
	if err != nil {
		t.Fatal(err)
	}
	if r.Network == nil || r.Network.FQDN == "" || r.Network.Timezone == "" || len(r.Network.Interfaces) == 0 {
		t.Fatalf("network: %+v", r.Network)
	}
	named := 0
	for _, p := range r.OpenPorts {
		if p.Addr == "" {
			t.Errorf("port without address: %+v", p)
		}
		if p.Process != "" {
			named++
		}
	}
	if len(r.OpenPorts) > 0 && named == 0 {
		t.Errorf("no listening port has its process: %+v", r.OpenPorts)
	}
	t.Logf("score %d, issues %v, gateway %q, dns %v, sessions %v", r.Score, r.Issues, r.Network.DefaultGateway,
		r.Network.DNSServers, r.Network.Sessions)
}
