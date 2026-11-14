package hygiene

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func collectNetworkPlatform(n *NetworkInfo) {
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		n.DefaultGateway = defaultGateway(string(b))
	}
	resolv, _ := os.ReadFile("/etc/resolv.conf")
	servers, domain := parseResolv(string(resolv))
	// systemd-resolved's stub (127.0.0.53) hides the real servers
	if onlyStub(servers) {
		if up, err := os.ReadFile("/run/systemd/resolve/resolv.conf"); err == nil {
			if s, d := parseResolv(string(up)); len(s) > 0 {
				servers = s
				if domain == "" {
					domain = d
				}
			}
		}
	}
	n.DNSServers, n.Domain = servers, domain
	if out, err := runTimeout("hostname", "-f"); err == nil {
		n.FQDN = strings.TrimSpace(out)
	}
	if n.FQDN == "" {
		n.FQDN, _ = os.Hostname()
	}
	if n.Domain == "" {
		if _, d, ok := strings.Cut(n.FQDN, "."); ok {
			n.Domain = d
		}
	}
	n.Timezone = localZoneName()
	if b, err := os.ReadFile("/var/run/utmp"); err == nil {
		n.Sessions = parseUtmp(b)
	} else if b, err := os.ReadFile("/run/utmp"); err == nil {
		n.Sessions = parseUtmp(b)
	}
}

// defaultGateway reads /proc/net/route: the IPv4 route to 0.0.0.0/0 with the
// gateway flag, addresses in host (little-endian) order.
func defaultGateway(route string) string {
	for _, line := range strings.Split(route, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 16)
		if flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	}
	return ""
}

func parseResolv(text string) (servers []string, domain string) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], ";") {
			continue
		}
		switch f[0] {
		case "nameserver":
			servers = append(servers, f[1])
		case "domain", "search":
			if domain == "" && f[1] != "." {
				domain = f[1]
			}
		}
	}
	return cleanList(servers), domain
}

func onlyStub(servers []string) bool {
	for _, s := range servers {
		if ip := net.ParseIP(s); ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return len(servers) > 0
}

// localZoneName: the IANA name /etc/localtime points to, else /etc/timezone.
func localZoneName() string {
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if _, name, ok := strings.Cut(link, "zoneinfo/"); ok {
			return name
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// utmp record layout (glibc, 64-bit and 32-bit alike): 384 bytes.
const (
	utmpSize        = 384
	utmpUserProcess = 7
)

// parseUtmp lists USER_PROCESS records: who is logged in, where from.
func parseUtmp(b []byte) []Session {
	var out []Session
	for off := 0; off+utmpSize <= len(b); off += utmpSize {
		rec := b[off : off+utmpSize]
		if int16(binary.LittleEndian.Uint16(rec[0:2])) != utmpUserProcess {
			continue
		}
		user := cstring(rec[44:76])
		if user == "" {
			continue
		}
		s := Session{User: user, Line: cstring(rec[8:40]), From: cstring(rec[76:332])}
		if sec := int32(binary.LittleEndian.Uint32(rec[340:344])); sec > 0 {
			s.Since = time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
		}
		if s.From == "" {
			if ip := utmpAddr(rec[348:364]); ip != "" {
				s.From = ip
			}
		}
		out = append(out, s)
	}
	return out
}

func utmpAddr(b []byte) string {
	if allZero(b[4:]) {
		if allZero(b[:4]) {
			return ""
		}
		return net.IP(b[:4]).String()
	}
	return net.IP(b).String()
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func cstring(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}
