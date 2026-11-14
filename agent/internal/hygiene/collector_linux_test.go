//go:build linux

package hygiene

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDefaultGatewayAndResolv(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t0000FEA9\t00000000\t0001\t0\t0\t0\t0000FFFF\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
	if gw := defaultGateway(route); gw != "192.168.1.1" {
		t.Fatalf("gateway %q", gw)
	}
	servers, domain := parseResolv("# generated\nnameserver 127.0.0.53\nnameserver 127.0.0.53\noptions edns0\nsearch corp.example .\n")
	if len(servers) != 1 || !onlyStub(servers) || domain != "corp.example" {
		t.Fatalf("%v %q", servers, domain)
	}
	if onlyStub([]string{"127.0.0.53", "1.1.1.1"}) || onlyStub(nil) {
		t.Fatal("a real resolver is not only the stub")
	}
}

func utmpRecord(typ int16, line, user, host string, sec int32, addr []byte) []byte {
	b := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(b[0:], uint16(typ))
	copy(b[8:40], line)
	copy(b[44:76], user)
	copy(b[76:332], host)
	binary.LittleEndian.PutUint32(b[340:], uint32(sec))
	copy(b[348:364], addr)
	return b
}

func TestParseUtmp(t *testing.T) {
	var data []byte
	data = append(data, utmpRecord(2, "~", "reboot", "7.0.0", 1, nil)...) // BOOT_TIME
	data = append(data, utmpRecord(7, "pts/0", "root", "103.204.15.34", 1794600000, nil)...)
	data = append(data, utmpRecord(7, "tty1", "admin", "", 1794600100, nil)...)
	data = append(data, utmpRecord(7, "pts/1", "deploy", "", 1794600200, []byte{10, 0, 0, 7})...)
	data = append(data, utmpRecord(8, "pts/2", "", "", 0, nil)...) // DEAD_PROCESS
	s := parseUtmp(data)
	if len(s) != 3 || s[0].User != "root" || s[0].From != "103.204.15.34" || s[0].Line != "pts/0" ||
		s[1].From != "" || s[2].From != "10.0.0.7" || s[0].Since != "2026-11-13T20:00:00Z" {
		t.Fatalf("%+v", s)
	}
}

func TestCollectReportsNetworkIdentity(t *testing.T) {
	r, _ := Collect("a", "h")
	n := r.Network
	if n == nil || n.FQDN == "" || n.UTCOffset == "" || n.BootTime == "" {
		t.Fatalf("network: %+v", n)
	}
	for _, i := range n.Interfaces {
		if i.Name == "lo" {
			t.Fatal("loopback is left out")
		}
	}
}

func TestProcNetListenAddresses(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109        0 4242 1 0000000000000000 100 0 0 10 0
   1: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   112        0 4243 1 0000000000000000 100 0 0 10 0
   2: 0F00A8C0:0016 0201A8C0:C350 01 00000000:00000000 02:000A7E5F 00000000     0        0 4244 4 0000000000000000 20 4 30 10 -1
`
	ports, inodes := parseListen(strings.NewReader(tcp), "tcp")
	if len(ports) != 2 || ports[0].Addr != "127.0.0.1" || ports[0].Port != 6379 || inodes[0] != "4242" ||
		ports[1].Addr != "0.0.0.0" || ports[1].Port != 3306 {
		t.Fatalf("v4: %+v %v", ports, inodes)
	}
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 77 1
   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 78 1
`
	ports, _ = parseListen(strings.NewReader(tcp6), "tcp6")
	if len(ports) != 2 || ports[0].Addr != "::1" || ports[0].Port != 80 || ports[1].Addr != "::" || !ports[1].Exposed() || ports[0].Exposed() {
		t.Fatalf("v6: %+v", ports)
	}
}

func TestParseRpmQuery(t *testing.T) {
	pkgs := parseRpmQuery("openssl\t3.0.7-27.el9\ngpg-pubkey\tfd431d51-4ae0493b\nbash\t5.1.8-9.el9\n\n")
	if len(pkgs) != 2 || pkgs[0].Name != "bash" || pkgs[1].Version != "3.0.7-27.el9" || pkgs[0].Source != "rpm" {
		t.Fatalf("%+v", pkgs)
	}
}

// The real collector on this machine: whatever it finds, it must not panic
// and every exposed port must carry its address.
func TestCollectOnThisHost(t *testing.T) {
	r, err := Collect("a", "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.OpenPorts {
		if p.Addr == "" {
			t.Errorf("port without address: %+v", p)
		}
	}
	if r.Score < 0 || r.Score > 100 {
		t.Fatalf("score %d", r.Score)
	}
}
