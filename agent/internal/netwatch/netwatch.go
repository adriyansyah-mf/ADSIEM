//go:build linux

// Package netwatch streams kernel network syscalls (connect, accept, bind,
// DNS sendto) into the log buffer as ECS-shaped events, so Sigma rules get
// more than what a text log happens to contain.
//
// Best-effort by design: without CAP_BPF/CAP_SYS_ADMIN or a mounted tracefs
// the attach fails, Start returns an error, and the caller falls back to
// periodic `ss` snapshots. Log tailing, FIM and firewall are unaffected.
package netwatch

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

//go:embed bpf/netwatch.bpf.o
var netwatchObj []byte

const (
	commLen    = 16
	hostLen    = 128
	recordSize = 8 + 4*4 + 4 + 2 + 2 + 4 + 4 + commLen + hostLen
)

const (
	syscallConnect = 1
	syscallBind    = 2
	syscallAccept  = 3
	syscallDNS     = 4
)

// selfComm is the agent's own process name. Its ingest traffic is the
// observer watching itself: emitting it floods the stream (one connect per
// shipped event) and buries real activity.
const selfComm = "agent"

// noiseComms are high-volume clients whose connect() calls carry no detection
// value at this granularity.
var noiseComms = map[string]struct{}{
	selfComm: {},
}

const (
	LogTypeConnect = "linux_network_connect"
	LogTypeAccept  = "linux_network_accept"
	LogTypeBind    = "linux_network_bind"
	LogTypeDNS     = "linux_dns_query"
)

type Monitor struct {
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	stopped chan struct{}
	bootAt  time.Time
}

type event struct {
	TimestampNS uint64
	PID         uint32
	TGID        uint32
	UID         uint32
	GID         uint32
	Syscall     uint8
	Family      uint8
	Proto       uint8
	Pad         uint8
	LocalPort   uint16
	RemotePort  uint16
	SAddrV4     uint32
	DAddrV4     uint32
	Comm        [commLen]byte
	Host        [hostLen]byte
}

// Start attaches every program in the object and streams events into buf.
func Start(buf *buffer.Buffer) (*Monitor, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netwatchObj))
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load collection into kernel: %w", err)
	}

	m := &Monitor{coll: coll, stopped: make(chan struct{}), bootAt: bootTime()}

	attached, err := m.attach()
	if err != nil {
		m.Close()
		return nil, err
	}

	eventsMap, ok := coll.Maps["net_events"]
	if !ok {
		m.Close()
		return nil, fmt.Errorf("ringbuf map %q not found", "net_events")
	}
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	m.reader = rd

	slog.Info("netwatch attached", "programs", attached)
	go m.readLoop(buf)
	return m, nil
}

func (m *Monitor) attach() ([]string, error) {
	targets := []struct {
		prog string
		cat  string
		name string
	}{
		{"handle_connect", "syscalls", "sys_enter_connect"},
		{"handle_bind", "syscalls", "sys_enter_bind"},
		{"handle_accept", "syscalls", "sys_enter_accept4"},
		{"handle_sendto", "syscalls", "sys_enter_sendto"},
	}

	var attached []string
	for _, t := range targets {
		prog, ok := m.coll.Programs[t.prog]
		if !ok {
			m.closeLinks()
			return nil, fmt.Errorf("program %q not found", t.prog)
		}
		l, err := link.Tracepoint(t.cat, t.name, prog, nil)
		if err != nil {
			m.closeLinks()
			return nil, fmt.Errorf("attach %s: %w", t.name, err)
		}
		m.links = append(m.links, l)
		attached = append(attached, t.name)
	}
	return attached, nil
}

func (m *Monitor) readLoop(buf *buffer.Buffer) {
	for {
		rec, err := m.reader.Read()
		if err != nil {
			select {
			case <-m.stopped:
				return
			default:
				slog.Warn("netwatch ringbuf read failed", "err", err)
				return
			}
		}
		if len(rec.RawSample) < recordSize {
			continue
		}
		ev := decode(rec.RawSample)
		if _, noisy := noiseComms[cstring(ev.Comm[:])]; noisy {
			continue
		}
		logType, line := render(ev, m.bootAt)
		if logType == "" {
			continue
		}
		buf.Push(tailer.Encode(logType, line))
	}
}

func (m *Monitor) Stop() {
	m.Close()
}

func (m *Monitor) Close() {
	select {
	case <-m.stopped:
	default:
		close(m.stopped)
	}
	if m.reader != nil {
		m.reader.Close()
	}
	m.closeLinks()
	if m.coll != nil {
		m.coll.Close()
	}
}

func (m *Monitor) closeLinks() {
	for _, l := range m.links {
		l.Close()
	}
	m.links = nil
}

func decode(raw []byte) event {
	var ev event
	off := 0

	ev.TimestampNS = binary.LittleEndian.Uint64(raw[off:])
	off += 8
	ev.PID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	ev.TGID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	ev.UID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	ev.GID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	ev.Syscall = raw[off]
	off++
	ev.Family = raw[off]
	off++
	ev.Proto = raw[off]
	off++
	ev.Pad = raw[off]
	off++
	ev.LocalPort = binary.LittleEndian.Uint16(raw[off:])
	off += 2
	ev.RemotePort = binary.LittleEndian.Uint16(raw[off:])
	off += 2
	ev.SAddrV4 = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	ev.DAddrV4 = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	copy(ev.Comm[:], raw[off:off+commLen])
	off += commLen
	copy(ev.Host[:], raw[off:off+hostLen])

	return ev
}

func render(ev event, bootAt time.Time) (string, string) {
	comm := cstring(ev.Comm[:])
	host := cstring(ev.Host[:])
	dst := uint32ToIP(ev.DAddrV4)
	src := uint32ToIP(ev.SAddrV4)

	var logType string
	var action string

	switch ev.Syscall {
	case syscallConnect:
		logType, action = LogTypeConnect, "network_connect"
	case syscallBind:
		logType, action = LogTypeBind, "network_bind"
	case syscallAccept:
		logType, action = LogTypeAccept, "network_accept"
	case syscallDNS:
		logType, action = LogTypeDNS, "dns_query"
	default:
		return "", ""
	}

	direction := "outbound"
	if ev.Syscall == syscallBind || ev.Syscall == syscallAccept {
		direction = "inbound"
	}

	line := fmt.Sprintf(
		"ts=%s pid=%d tgid=%d uid=%d gid=%d comm=%s action=%s proto=%s direction=%s src=%s dport=%d dst=%s lport=%d host=%s private_dst=%t",
		bootAt.Add(time.Duration(ev.TimestampNS)).UTC().Format(time.RFC3339Nano),
		ev.PID, ev.TGID, ev.UID, ev.GID, comm, action, protoName(ev.Proto), direction,
		src, ev.RemotePort, dst, ev.LocalPort, host, isPrivate(dst),
	)
	return logType, line
}

// bootTime turns bpf_ktime_get_ns() (nanoseconds since boot) into a wall
// clock instant. The agent's own clock is trusted; kernel and userspace share
// CLOCK_REALTIME on Linux.
func bootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Now().UTC()
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil {
			return time.Now().UTC()
		}
		return time.Unix(secs, 0).UTC()
	}
	return time.Now().UTC()
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "other"
	}
}

func uint32ToIP(v uint32) string {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r < 32 || r > 126 {
			continue
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
