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

// Stop is a no-op off Windows.
func (*Sensor) Stop() {}
