//go:build !windows

package winsensor

import (
	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/etw"
)

// Sensor is the Windows ETW sensor; off Windows it cannot start.
type Sensor struct{}

// Start is only available on Windows.
func Start(*buffer.Buffer) (*Sensor, error) { return nil, etw.ErrUnsupported }

// SysmonInstalled is always false off Windows.
func SysmonInstalled() bool { return false }

// Dropped is always 0 off Windows.
func (*Sensor) Dropped() uint64 { return 0 }

// Stop is a no-op off Windows.
func (*Sensor) Stop() {}
