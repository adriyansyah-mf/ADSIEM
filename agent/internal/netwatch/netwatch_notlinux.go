//go:build !linux

package netwatch

import (
	"errors"

	"github.com/siem-platform/agent/internal/buffer"
)

type Monitor struct{}

func Start(buf *buffer.Buffer) (*Monitor, error) {
	return nil, errors.New("netwatch requires Linux")
}

func (m *Monitor) Stop() {}

type Snapshotter struct{}

func StartSnapshotter(buf *buffer.Buffer, _ string) *Snapshotter {
	return &Snapshotter{}
}

func (s *Snapshotter) Stop() {}
