package firewall

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

var alwaysProtected = []string{
	"127.0.0.0/8",
	"169.254.0.0/16",
	"0.0.0.0/32",
}

type Guard struct {
	serverURL   string
	extraIPs    []string
	mu          sync.RWMutex
	resolved    []*net.IPNet
	resolveErr  error
	gateway     *net.IPNet
	gatewayRead bool
}

func NewGuard(serverURL string, extraIPs []string) *Guard {
	g := &Guard{serverURL: serverURL, extraIPs: extraIPs}
	g.Refresh()
	return g
}

func (g *Guard) SetServerURL(raw string) {
	g.mu.Lock()
	g.serverURL = raw
	g.mu.Unlock()
	g.Refresh()
}

func (g *Guard) Refresh() {
	g.mu.RLock()
	host := hostFromURL(g.serverURL)
	extra := g.extraIPs
	g.mu.RUnlock()

	var nets []*net.IPNet
	for _, c := range alwaysProtected {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}

	var resolveErr error
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			nets = append(nets, hostNet(ip))
			if n := localNetFor(ip); n != nil {
				nets = append(nets, n)
			}
		} else {
			addrs, err := net.LookupHost(host)
			if err != nil || len(addrs) == 0 {
				resolveErr = fmt.Errorf("cannot resolve %s: %w", host, err)
			} else {
				for _, a := range addrs {
					if ip := net.ParseIP(a); ip != nil {
						nets = append(nets, hostNet(ip))
						if n := localNetFor(ip); n != nil {
							nets = append(nets, n)
						}
					}
				}
			}
		}
	}

	for _, c := range extra {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			nets = append(nets, hostNet(ip))
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}

	g.mu.Lock()
	g.resolved = nets
	g.resolveErr = resolveErr
	g.mu.Unlock()
}

func (g *Guard) Gateway() *net.IPNet {
	g.mu.RLock()
	if g.gatewayRead {
		gw := g.gateway
		g.mu.RUnlock()
		return gw
	}
	g.mu.RUnlock()

	gw := readDefaultGateway()

	g.mu.Lock()
	g.gateway = gw
	g.gatewayRead = true
	g.mu.Unlock()
	return gw
}

func (g *Guard) Protect(rule Rule) error {
	if rule.Action != ActionBlock {
		return nil
	}

	targetIP, targetNet, err := parseTarget(rule.CIDR)
	if err != nil {
		return err
	}

	g.mu.RLock()
	nets := g.resolved
	g.mu.RUnlock()

	for _, p := range nets {
		if p.Contains(targetIP) {
			return fmt.Errorf("refusing to block %s: overlaps protected network %s", rule.CIDR, p.String())
		}
		if targetNet.Contains(p.IP) {
			return fmt.Errorf("refusing to block %s: it contains protected address %s", rule.CIDR, p.IP)
		}
	}

	if gw := g.Gateway(); gw != nil {
		if gw.Contains(targetIP) {
			return fmt.Errorf("refusing to block %s: it is the default gateway", rule.CIDR)
		}
		if targetNet.Contains(gw.IP) {
			return fmt.Errorf("refusing to block %s: it contains the default gateway %s", rule.CIDR, gw.IP)
		}
	}

	return nil
}

func (g *Guard) ProtectedCIDRs() []string {
	gw := g.Gateway()

	g.mu.RLock()
	out := make([]string, 0, len(g.resolved)+1)
	for _, n := range g.resolved {
		out = append(out, n.String())
	}
	g.mu.RUnlock()

	if gw != nil {
		out = append(out, gw.String())
	}
	return out
}

func (g *Guard) ResolveError() error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.resolveErr
}

func parseTarget(cidr string) (net.IP, *net.IPNet, error) {
	if ip := net.ParseIP(cidr); ip != nil {
		return ip, hostNet(ip), nil
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}
	return n.IP, n, nil
}

func hostNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

func readDefaultGateway() *net.IPNet {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		ip := parseHexIPv4LE(fields[2])
		if ip == nil {
			return nil
		}
		return hostNet(ip)
	}
	return nil
}

func parseHexIPv4LE(hex string) net.IP {
	if len(hex) != 8 {
		return nil
	}
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		var v int
		if _, err := fmt.Sscanf(hex[i*2:i*2+2], "%02x", &v); err != nil {
			return nil
		}
		b[3-i] = byte(v)
	}
	return net.IPv4(b[0], b[1], b[2], b[3])
}
