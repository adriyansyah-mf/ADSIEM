//go:build linux

package netwatch

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func encodeEvent(ev event) []byte {
	buf := make([]byte, recordSize)
	off := 0
	binary.LittleEndian.PutUint64(buf[off:], ev.TimestampNS)
	off += 8
	for _, v := range []uint32{ev.PID, ev.TGID, ev.UID, ev.GID} {
		binary.LittleEndian.PutUint32(buf[off:], v)
		off += 4
	}
	buf[off] = ev.Syscall
	off++
	buf[off] = ev.Family
	off++
	buf[off] = ev.Proto
	off++
	buf[off] = ev.Pad
	off++
	binary.LittleEndian.PutUint16(buf[off:], ev.LocalPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], ev.RemotePort)
	off += 2
	binary.LittleEndian.PutUint32(buf[off:], ev.SAddrV4)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], ev.DAddrV4)
	off += 4
	copy(buf[off:], ev.Comm[:])
	off += commLen
	copy(buf[off:], ev.Host[:])
	return buf
}

func TestDecodeMatchesStructLayout(t *testing.T) {
	var comm [commLen]byte
	copy(comm[:], "curl")
	var host [hostLen]byte
	copy(host[:], "example.org")

	in := event{
		TimestampNS: 1_700_000_000_000_000_000,
		PID:         4242,
		TGID:        4242,
		UID:         1000,
		GID:         1000,
		Syscall:     syscallConnect,
		Family:      2,
		Proto:       6,
		LocalPort:   51234,
		RemotePort:  443,
		DAddrV4:     0x0100007F,
		Comm:        comm,
		Host:        host,
	}

	out := decode(encodeEvent(in))
	if out.PID != in.PID || out.RemotePort != in.RemotePort || out.Syscall != in.Syscall {
		t.Fatalf("decode mismatch: %+v", out)
	}
	if cstring(out.Comm[:]) != "curl" {
		t.Fatalf("comm mismatch: %q", cstring(out.Comm[:]))
	}
	if cstring(out.Host[:]) != "example.org" {
		t.Fatalf("host mismatch: %q", cstring(out.Host[:]))
	}
}

func TestRenderEmitsWantedLogTypes(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)

	cases := map[uint8]string{
		syscallConnect: LogTypeConnect,
		syscallBind:    LogTypeBind,
		syscallAccept:  LogTypeAccept,
		syscallDNS:     LogTypeDNS,
	}
	for kind, wantLogType := range cases {
		var comm [commLen]byte
		copy(comm[:], "test")
		ev := event{Syscall: kind, Proto: 6, Comm: comm, TimestampNS: uint64(time.Second)}
		got, line := render(ev, boot)
		if got != wantLogType {
			t.Errorf("syscall %d: got %q want %q", kind, got, wantLogType)
		}
		if !strings.Contains(line, "comm=test") {
			t.Errorf("syscall %d: missing comm in %q", kind, line)
		}
		if !strings.Contains(line, "ts=2023-11-14T22:13:21") {
			t.Errorf("syscall %d: timestamp not anchored to boot time: %q", kind, line)
		}
	}

	if got, _ := render(event{Syscall: 99}, boot); got != "" {
		t.Errorf("unknown syscall must be dropped, got %q", got)
	}
}

func TestRenderMarksPrivateDestination(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	var comm [commLen]byte

	private := event{Syscall: syscallConnect, Proto: 6, Comm: comm, DAddrV4: 0x0100000A}
	if _, line := render(private, boot); !strings.Contains(line, "private_dst=true") {
		t.Fatalf("10.0.0.1 must be private: %q", line)
	}

	public := event{Syscall: syscallConnect, Proto: 6, Comm: comm, DAddrV4: 0x050302CB}
	if _, line := render(public, boot); !strings.Contains(line, "private_dst=false") {
		t.Fatalf("203.2.3.5 must be public: %q", line)
	}
}

func TestUint32ToIP(t *testing.T) {
	if got := uint32ToIP(0x0100007F); got != "127.0.0.1" {
		t.Errorf("got %s want 127.0.0.1", got)
	}
}

func TestAgentOwnTrafficIsFiltered(t *testing.T) {
	var comm [commLen]byte
	copy(comm[:], selfComm)
	if _, noisy := noiseComms[cstring(comm[:])]; !noisy {
		t.Fatal("the agent's own process must be treated as noise")
	}

	var other [commLen]byte
	copy(other[:], "curl")
	if _, noisy := noiseComms[cstring(other[:])]; noisy {
		t.Fatal("unrelated processes must not be filtered")
	}
}

func TestCStringStripsNonPrintable(t *testing.T) {
	b := []byte{'a', 0xff, 'b', 0x00, 'c'}
	if got := cstring(b); got != "ab" {
		t.Fatalf("got %q want %q", got, "ab")
	}
}

func TestProtoName(t *testing.T) {
	if protoName(6) != "tcp" || protoName(17) != "udp" || protoName(1) != "icmp" {
		t.Error("proto mapping broken")
	}
	if protoName(132) != "other" {
		t.Error("unknown proto must map to other")
	}
}
