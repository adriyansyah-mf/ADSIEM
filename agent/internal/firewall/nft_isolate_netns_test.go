//go:build linux

package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The isolation table against the real kernel, in a throwaway network
// namespace (`unshare -rn`: no root, nothing on the host touched). Packets to
// the allow list leave; anything else (IPv4 and IPv6) is refused by the
// output chain. FIREWALL_NETNS_E2E=1 runs it (needs nft and user namespaces).
func TestIsolationTableInANetworkNamespace(t *testing.T) {
	if os.Getenv("FIREWALL_NETNS_E2E") != "1" {
		t.Skip("set FIREWALL_NETNS_E2E=1 (needs nft and unprivileged user namespaces)")
	}
	dir := t.TempDir()
	isolate := filepath.Join(dir, "isolate.nft")
	release := filepath.Join(dir, "release.nft")
	// allow the "server" 10.9.9.2 and its v6 twin; 10.9.9.3 / fd00::3 are anyone else
	if err := os.WriteFile(isolate, []byte(nftIsolateScript([]string{"127.0.0.0/8", "10.9.9.2/32", "fd00::2/128",
		"fe80::/10", "ff02::/16", "10.9.9.2"})), 0o600); err != nil { // a duplicate on purpose: auto-merge
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("table inet "+isolateTable+" {}\ndelete table inet "+isolateTable+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -u
ip link set lo up
ip link add d0 type dummy && ip link set d0 up
ip addr add 10.9.9.1/24 dev d0
ip -6 addr add fd00::1/64 dev d0 nodad
# a UDP datagram the output chain drops fails in sendto with EPERM; an allowed
# one leaves (nobody answers on a dummy link: that's fine). ping is no use
# here: an ICMP socket loses a dropped packet without an error.
send() { if bash -c "echo x > /dev/udp/$2/9" 2>/dev/null; then echo sent; else echo blocked; fi; }
nft -f ` + isolate + ` || { echo APPLY_FAILED; exit 1; }
nft -f ` + isolate + ` || { echo REAPPLY_FAILED; exit 1; }
echo "server4=$(send -4 10.9.9.2)"
echo "other4=$(send -4 10.9.9.3)"
echo "server6=$(send -6 fd00::2)"
echo "other6=$(send -6 fd00::3)"
echo "loopback=$(send -4 127.0.0.1)"
nft -f ` + release + ` || { echo RELEASE_FAILED; exit 1; }
nft list tables | grep -q ` + isolateTable + ` && echo table_left || echo table_gone
echo "after4=$(send -4 10.9.9.3)"
`
	out, err := exec.Command("unshare", "-rn", "sh", "-c", script).CombinedOutput()
	got := string(out)
	if err != nil {
		t.Fatalf("netns run: %v\n%s", err, got)
	}
	for _, want := range []string{"server4=sent", "other4=blocked", "server6=sent", "other6=blocked",
		"loopback=sent", "table_gone", "after4=sent"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
