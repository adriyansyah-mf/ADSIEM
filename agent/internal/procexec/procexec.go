// Package procexec streams process-exec events (Sigma "process_creation"
// logsource: Image, CommandLine, ParentImage, PPID, User) into the log
// buffer by attaching an eBPF program to tracepoint/syscalls/sys_enter_execve.
//
// This is best-effort: older kernels (no BTF), missing CAP_BPF/CAP_SYS_ADMIN,
// or a kernel built without CONFIG_DEBUG_INFO_BTF will fail to load. In all
// of those cases Start logs a warning and returns — the rest of the agent
// (log tailing, FIM, hygiene, live response) is unaffected.
package procexec

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/siem-platform/agent/internal/buffer"
)

//go:embed bpf/execve.bpf.o
var execveObj []byte

const (
	commLen       = 16
	filenameLen   = 256
	argsBufLen    = 512
	recordMinSize = 8 + 4*4 + commLen + filenameLen*2 + argsBufLen + 4 + 4 + 1
)

const LogType = "linux_process_exec"

type Monitor struct {
	coll    *ebpf.Collection
	link    link.Link
	reader  *ringbuf.Reader
	stopped chan struct{}
}

// Start attaches the execve tracepoint program and begins pushing decoded
// exec events into buf. Returns (nil, err) if eBPF isn't usable on this
// host — callers should treat that as non-fatal.
func Start(buf *buffer.Buffer) (*Monitor, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(execveObj))
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load collection into kernel: %w", err)
	}

	prog, ok := coll.Programs["handle_execve"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("program %q not found in object", "handle_execve")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		tp.Close()
		coll.Close()
		return nil, fmt.Errorf("ringbuf map %q not found in object", "events")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		tp.Close()
		coll.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	m := &Monitor{coll: coll, link: tp, reader: rd, stopped: make(chan struct{})}
	go m.loop(buf)
	slog.Info("procexec: attached to tracepoint/syscalls/sys_enter_execve")
	return m, nil
}

func (m *Monitor) Stop() {
	close(m.stopped)
	m.reader.Close()
	m.link.Close()
	m.coll.Close()
}

func (m *Monitor) loop(buf *buffer.Buffer) {
	for {
		record, err := m.reader.Read()
		if err != nil {
			select {
			case <-m.stopped:
				return
			default:
			}
			if err == ringbuf.ErrClosed {
				return
			}
			slog.Warn("procexec: ringbuf read error", "err", err)
			continue
		}
		raw, ok := decodeEvent(record.RawSample)
		if !ok {
			continue
		}
		buf.Push(LogType + "\x00" + raw)
	}
}

// decodeEvent parses the fixed-layout struct exec_event emitted by
// execve.bpf.c (see bpf/execve.bpf.c for the authoritative field order/
// offsets — this must be kept in sync with that struct).
func decodeEvent(b []byte) (string, bool) {
	if len(b) < recordMinSize {
		return "", false
	}
	off := 0
	_ = binary.LittleEndian.Uint64(b[off:]) // timestamp_ns, unused for now
	off += 8
	pid := binary.LittleEndian.Uint32(b[off:])
	off += 4
	ppid := binary.LittleEndian.Uint32(b[off:])
	off += 4
	uid := binary.LittleEndian.Uint32(b[off:])
	off += 4
	off += 4 // gid, unused for now

	comm := cstr(b[off : off+commLen])
	off += commLen
	filename := cstr(b[off : off+filenameLen])
	off += filenameLen
	parentFilename := cstr(b[off : off+filenameLen])
	off += filenameLen
	argsBuf := b[off : off+argsBufLen]
	off += argsBufLen
	argsSize := binary.LittleEndian.Uint32(b[off:])
	off += 4
	_ = binary.LittleEndian.Uint32(b[off:]) // args_count, unused for now
	off += 4
	truncated := b[off] != 0

	if filename == "" {
		return "", false
	}

	commandLine := joinArgs(argsBuf, int(argsSize))
	if commandLine == "" {
		commandLine = filename
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `Image=%s CommandLine=%s PID=%d PPID=%d User=%d`,
		kv(filename), kv(commandLine), pid, ppid, uid)
	if parentFilename != "" {
		fmt.Fprintf(&sb, ` ParentImage=%s`, kv(parentFilename))
	}
	if comm != "" {
		fmt.Fprintf(&sb, ` Comm=%s`, kv(comm))
	}
	if truncated {
		sb.WriteString(` ArgsTruncated=true`)
	}
	return sb.String(), true
}

// joinArgs reassembles the flat NUL-separated argv buffer (as written by
// the eBPF program) into a single space-joined command line.
func joinArgs(buf []byte, size int) string {
	if size <= 0 || size > len(buf) {
		size = len(buf)
	}
	var parts []string
	start := 0
	for i := 0; i < size; i++ {
		if buf[i] == 0 {
			if i > start {
				parts = append(parts, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	return strings.Join(parts, " ")
}

func cstr(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// kv quotes a value for the decoder's key="value" grammar, escaping
// embedded quotes/backslashes.
func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
