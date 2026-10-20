//go:build linux

package netwatch

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

const (
	LogTypeSnapshot = "linux_network_snapshot"
	snapshotEvery   = 10 * time.Second
	// a host with a connection storm still can't flood the pipeline
	maxNewPerSnapshot = 500
)

// Snapshotter periodically records `ss` output. It is the fallback when eBPF
// is unavailable (no CAP_BPF, no tracefs), so the SIEM still receives network
// state instead of nothing at all.
//
// Only connections that weren't there in the previous snapshot are sent:
// shipping every socket every 10 s was millions of lines a day of the same
// connections. TIME-WAIT, loopback-only and the agent's own connections to
// the SIEM server are skipped (the latter grew with every batch it shipped).
type Snapshotter struct {
	stop chan struct{}
	skip map[string]bool // SIEM server "ip:port"
}

func StartSnapshotter(buf *buffer.Buffer, serverURL string) *Snapshotter {
	s := &Snapshotter{stop: make(chan struct{}), skip: serverEndpoints(serverURL)}
	go s.loop(buf)
	return s
}

func (s *Snapshotter) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// serverEndpoints resolves the SIEM server URL to the "ip:port" peers to ignore.
func serverEndpoints(serverURL string) map[string]bool {
	out := map[string]bool{}
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return out
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	ips, err := net.LookupHost(u.Hostname())
	if err != nil {
		ips = []string{u.Hostname()}
	}
	for _, ip := range ips {
		out[net.JoinHostPort(ip, port)] = true
	}
	return out
}

// splitHostPort accepts ss's "1.2.3.4:80", "[::1]:80", "*:*" and "1.2.3.4%eth0:80".
func splitHostPort(addr string) (string, string) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, ""
	}
	host := strings.Trim(addr[:i], "[]")
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	return host, addr[i+1:]
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newConnections returns the lines of an `ss -tunapH` snapshot whose connection
// wasn't in prev, and the set to compare the next snapshot against.
func newConnections(out string, prev map[string]bool, skip map[string]bool) ([]string, map[string]bool) {
	seen := map[string]bool{}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] == "Netid" {
			continue
		}
		netid, state, local, peer := f[0], f[1], f[4], f[5]
		if state == "TIME-WAIT" {
			continue
		}
		lh, _ := splitHostPort(local)
		ph, pp := splitHostPort(peer)
		if isLoopback(lh) && (isLoopback(ph) || ph == "*") {
			continue
		}
		if skip[net.JoinHostPort(ph, pp)] {
			continue
		}
		process := ""
		if len(f) > 6 {
			process = strings.Join(f[6:], " ")
			if i := strings.Index(process, ",pid="); i >= 0 { // the process name, not its fd
				process = process[:i]
			}
		}
		key := netid + " " + state + " " + local + " " + peer + " " + process
		if seen[key] {
			continue
		}
		seen[key] = true
		if !prev[key] {
			lines = append(lines, line)
		}
	}
	return lines, seen
}

func (s *Snapshotter) loop(buf *buffer.Buffer) {
	var prev map[string]bool
	emit := func() {
		out, err := s.read()
		if err != nil {
			return
		}
		lines, seen := newConnections(out, prev, s.skip)
		prev = seen
		if len(lines) > maxNewPerSnapshot {
			slog.Warn("netwatch snapshot: too many new connections, sending the first ones",
				"new", len(lines), "sent", maxNewPerSnapshot)
			lines = lines[:maxNewPerSnapshot]
		}
		for _, line := range lines {
			buf.Push(tailer.Encode(LogTypeSnapshot, line))
		}
	}

	emit()
	ticker := time.NewTicker(snapshotEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			emit()
		}
	}
}

func (s *Snapshotter) read() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ss", "-tunapH").CombinedOutput()
	if err != nil {
		slog.Warn("netwatch snapshot failed", "err", err)
		return "", err
	}
	return string(out), nil
}
