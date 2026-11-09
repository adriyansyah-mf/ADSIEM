// Package etw consumes Event Tracing for Windows in real time, without cgo or
// a driver: a session per Config, events decoded generically through TDH into
// named string properties. It is the Windows counterpart of the eBPF sensors
// (procexec, netwatch): the agent turns these events into process, network
// and DNS lines.
package etw

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"
)

// ErrUnsupported is returned off Windows.
var ErrUnsupported = errors.New("etw: only available on Windows")

// Provider is a manifest (or TraceLogging) provider to enable in a session.
type Provider struct {
	GUID     string // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
	Level    uint8  // 0 means all levels (5, verbose)
	Keywords uint64 // MatchAnyKeyword; 0 means all
	// EventIDs, when set, are the only events the kernel delivers from this
	// provider (an EVENT_FILTER_TYPE_EVENT_ID filter): Kernel-Network's per
	// packet send/receive events never reach the agent.
	EventIDs []uint16
}

// Config is one real-time session. A session with KernelFlags is a private
// system logger session (Windows 8+) receiving the kernel's own events, such
// as process start with its command line; it takes no Providers.
type Config struct {
	Name        string
	Providers   []Provider
	KernelFlags uint32
	// Fast events skip TDH: the Event carries the header (ID, PID, TID,
	// time) and Value, no Props. For very frequent events whose one needed
	// field sits at a fixed offset (Kernel-File Write's FileObject).
	Fast []Fast
}

// Fast decodes events of one ID by reading a pointer-sized field at the
// byte offset Offset returns for the event's pointer size (4 or 8) into
// Event.Value. An event too short for it has Value 0.
type Fast struct {
	ID     uint16
	Offset func(pointerSize int) int
	// Versions are the event versions whose layout Offset knows; other
	// versions are decoded with TDH. Empty means all.
	Versions []uint8
	// Field is the TDH property Offset reads. The first Verify events are
	// decoded both ways and compared: on any mismatch the fast decode is
	// switched off for the session (TDH from then on).
	Field  string
	Verify int
}

// fastGate decides, per event, between the fast decode and TDH, and keeps
// the self-check's counts. Safe for concurrent use.
type fastGate struct {
	field      string
	versions   map[uint8]bool
	verifyLeft atomic.Int64
	verified   atomic.Uint64
	mismatches atomic.Uint64
	off        atomic.Bool
}

func newFastGate(f Fast) *fastGate {
	g := &fastGate{field: f.Field}
	if len(f.Versions) > 0 {
		g.versions = map[uint8]bool{}
		for _, v := range f.Versions {
			g.versions[v] = true
		}
	}
	g.verifyLeft.Store(int64(f.Verify))
	return g
}

// plan says how to decode an event of version v: fast (the fast value is
// wanted) and check (decode with TDH too and call result).
func (g *fastGate) plan(v uint8) (fast, check bool) {
	if g.off.Load() || (g.versions != nil && !g.versions[v]) {
		return false, false
	}
	if g.verifyLeft.Load() > 0 && g.verifyLeft.Add(-1) >= 0 {
		return true, true
	}
	return true, false
}

// result records a check: the value TDH decoded (ok: it had the field)
// against the fast one. A mismatch switches the fast decode off.
func (g *fastGate) result(tdh, fast uint64, ok bool) {
	if ok && tdh == fast {
		g.verified.Add(1)
		return
	}
	g.mismatches.Add(1)
	g.off.Store(true)
}

func (g *fastGate) stats() (verified, mismatches uint64, off bool) {
	return g.verified.Load(), g.mismatches.Load(), g.off.Load()
}

// FastStats is the fast decode's self-check: events verified against TDH,
// mismatches, and whether the fast decode was switched off.
type FastStats struct {
	Verified, Mismatches uint64
	Off                  bool
}

// fastValue reads the pointer-sized little-endian value at off in data.
func fastValue(data []byte, pointerSize, off int) (uint64, bool) {
	if off < 0 || off+pointerSize > len(data) {
		return 0, false
	}
	if pointerSize == 4 {
		return uint64(binary.LittleEndian.Uint32(data[off:])), true
	}
	return binary.LittleEndian.Uint64(data[off:]), true
}

// Kernel event groups for Config.KernelFlags (EVENT_TRACE_FLAG_*).
const (
	KernelProcess      = 0x00000001
	KernelNetworkTCPIP = 0x00010000
)

// Property is one decoded event field, formatted by TDH.
type Property struct {
	Name, Value string
}

// Event is one decoded event. Truncated means decoding stopped early (a
// struct or array property): Props holds the fields before it.
type Event struct {
	Provider     string // GUID
	ProviderName string
	ID           uint16
	Version      uint8
	Opcode       uint8
	Task         uint16
	PID, TID     uint32
	Time         time.Time
	Props        []Property
	Truncated    bool
	// Value is the field a Fast decode read (Config.Fast); 0 otherwise.
	Value uint64
}

// Get returns the value of the named property and whether it is present.
func (e *Event) Get(name string) (string, bool) {
	for _, p := range e.Props {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}
