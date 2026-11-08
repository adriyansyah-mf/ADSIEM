// Package etw consumes Event Tracing for Windows in real time, without cgo or
// a driver: a session per Config, events decoded generically through TDH into
// named string properties. It is the Windows counterpart of the eBPF sensors
// (procexec, netwatch): the agent turns these events into process, network
// and DNS lines.
package etw

import (
	"encoding/binary"
	"errors"
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
