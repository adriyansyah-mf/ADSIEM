// Package sensorstat counts what each telemetry sensor delivers, for the
// heartbeat's sensor_health: the server alerts when a sensor that was running
// stops, goes silent while the agent still heartbeats, or loses events
// (server-api app/services/sensor_health.py). The counts are taken where
// lines enter the agent's buffer, so a slow or unreachable server never makes
// a sensor look silent.
package sensorstat

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/tailer"
)

// Sensor names as the server sees them.
const (
	ETW       = "etw"       // Windows: winsensor (process, network, file, image, registry, access)
	ProcExec  = "procexec"  // Linux: eBPF execve
	Netwatch  = "netwatch"  // Linux: eBPF connect/accept/bind/DNS, or the ss snapshot fallback
	LinSensor = "linsensor" // Linux: eBPF file, module, ptrace, privilege, memfd, exit
)

// Stat is one sensor's state in the heartbeat.
type Stat struct {
	Running     bool   `json:"running"`
	Events      uint64 `json:"events"`
	LastEventAt string `json:"last_event_at,omitempty"`
	Lost        uint64 `json:"lost"`
	Error       string `json:"error,omitempty"`
}

type sensor struct {
	running atomic.Bool
	events  atomic.Uint64
	last    atomic.Int64 // unix seconds of the last event
	mu      sync.Mutex
	err     string
	lost    func() uint64
}

// Registry holds every sensor's counters.
type Registry struct {
	mu      sync.RWMutex
	sensors map[string]*sensor
}

// Default is the agent's registry.
var Default = New()

// New returns an empty registry.
func New() *Registry { return &Registry{sensors: map[string]*sensor{}} }

func (r *Registry) get(name string) *sensor {
	r.mu.RLock()
	s := r.sensors[name]
	r.mu.RUnlock()
	if s != nil {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s = r.sensors[name]; s == nil {
		s = &sensor{}
		r.sensors[name] = s
	}
	return s
}

// SensorOf maps a log type to the sensor that produces it ("" = none counted).
func SensorOf(logType string) string {
	switch {
	case logType == "windows_etw_status":
		return "" // the sensor's own health report, not telemetry
	case strings.HasPrefix(logType, "windows_etw_"):
		return ETW
	case logType == "linux_process_exec":
		return ProcExec
	case strings.HasPrefix(logType, "linux_network_"), logType == "linux_dns_query":
		return Netwatch
	}
	switch logType {
	case "linux_file_event", "linux_kernel_module", "linux_ptrace", "linux_privilege_change",
		"linux_memfd_create", "linux_fileless_exec", "linux_process_exit", "linux_process_access":
		return LinSensor
	}
	return ""
}

// Observe counts one buffered entry (the buffer's observer).
func (r *Registry) Observe(entry string) {
	logType, _, _ := tailer.Decode(entry)
	name := SensorOf(logType)
	if name == "" {
		return
	}
	s := r.get(name)
	s.events.Add(1)
	s.last.Store(time.Now().Unix())
}

// SetRunning records whether a sensor started (err: why not, or why it stopped).
func (r *Registry) SetRunning(name string, running bool, err string) {
	s := r.get(name)
	s.running.Store(running)
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// SetLost registers a counter of events the sensor lost (kernel buffers, a
// full queue); it is read at every heartbeat.
func (r *Registry) SetLost(name string, f func() uint64) {
	s := r.get(name)
	s.mu.Lock()
	s.lost = f
	s.mu.Unlock()
}

// Snapshot is the heartbeat's sensor_health: every sensor that was started
// or has produced events.
func (r *Registry) Snapshot() map[string]Stat {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Stat, len(r.sensors))
	for name, s := range r.sensors {
		st := Stat{Running: s.running.Load(), Events: s.events.Load()}
		if t := s.last.Load(); t > 0 {
			st.LastEventAt = time.Unix(t, 0).UTC().Format(time.RFC3339)
		}
		s.mu.Lock()
		st.Error = s.err
		if s.lost != nil {
			st.Lost = s.lost()
		}
		s.mu.Unlock()
		if st.Running || st.Events > 0 || st.Error != "" {
			out[name] = st
		}
	}
	return out
}
