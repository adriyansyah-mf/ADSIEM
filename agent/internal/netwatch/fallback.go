//go:build linux

package netwatch

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

const (
	LogTypeSnapshot = "linux_network_snapshot"
	snapshotEvery   = 10 * time.Second
)

// Snapshotter periodically records `ss` output. It is the fallback when eBPF
// is unavailable (no CAP_BPF, no tracefs), so the SIEM still receives network
// state instead of nothing at all.
type Snapshotter struct {
	stop chan struct{}
}

func StartSnapshotter(buf *buffer.Buffer) *Snapshotter {
	s := &Snapshotter{stop: make(chan struct{})}
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

func (s *Snapshotter) loop(buf *buffer.Buffer) {
	emit := func() {
		out, err := s.read()
		if err != nil {
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line == "" || strings.HasPrefix(line, "Netid") {
				continue
			}
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
