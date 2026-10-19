package firewall

import (
	"net"
)

// localNetFor returns the on-link subnet the agent uses to reach ip, taken
// from the host's own interface list. Protecting only the resolved single
// address is not enough: in a container network the server and its peers sit
// in the same /16, and a server-driven rule targeting a sibling address (or
// the whole subnet) would cut the management path without touching the
// resolved IP itself.
func localNetFor(ip net.IP) *net.IPNet {
	if ip == nil || ip.To4() == nil {
		return nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() == nil {
				continue
			}
			if ipnet.Contains(ip) && !ipnet.IP.Equal(ip) {
				return ipnet
			}
		}
	}
	return nil
}
