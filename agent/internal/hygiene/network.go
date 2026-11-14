package hygiene

// Network identity shared by every platform: interfaces come from the Go
// runtime (the same on Linux and Windows); gateway, DNS, names, time zone and
// sessions from each platform's collectNetworkPlatform.

import (
	"net"
	"sort"
	"strings"
	"time"
)

const (
	maxInterfaces = 32
	maxSessions   = 64
)

func collectNetwork(r *Report, now time.Time) {
	n := &NetworkInfo{Interfaces: interfaces()}
	_, offset := now.Zone()
	n.UTCOffset = utcOffset(offset)
	if r.UptimeSecs > 0 {
		n.BootTime = now.Add(-time.Duration(r.UptimeSecs) * time.Second).UTC().Format(time.RFC3339)
	}
	collectNetworkPlatform(n)
	if len(n.Sessions) > maxSessions {
		n.Sessions = n.Sessions[:maxSessions]
	}
	r.Network = n
}

// interfaces lists the host's interfaces with addresses, loopback left out.
func interfaces() []NetInterface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []NetInterface
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		ni := NetInterface{Name: i.Name, MAC: i.HardwareAddr.String(), Up: i.Flags&net.FlagUp != 0}
		for _, a := range addrs {
			ni.Addrs = append(ni.Addrs, a.String())
		}
		if len(ni.Addrs) == 0 && ni.MAC == "" {
			continue // tunnels and placeholders with nothing to say
		}
		out = append(out, ni)
	}
	// interfaces with addresses first: the ones an IP in an alert can match
	sort.SliceStable(out, func(a, b int) bool { return len(out[a].Addrs) > 0 && len(out[b].Addrs) == 0 })
	if len(out) > maxInterfaces {
		out = out[:maxInterfaces]
	}
	return out
}

func utcOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign, seconds = "-", -seconds
	}
	h, m := seconds/3600, seconds%3600/60
	return sign + two(h) + ":" + two(m)
}

func two(n int) string {
	return string([]byte{byte('0' + n/10%10), byte('0' + n%10)})
}

// cleanList drops empty and duplicate entries, keeping order.
func cleanList(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
