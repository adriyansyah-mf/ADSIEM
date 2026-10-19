package tailer

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/winevent"
)

// EventLogPrefix marks a log source that is a Windows Event Log channel rather
// than a file, e.g. "eventlog:Security" or "eventlog:Microsoft-Windows-Sysmon/Operational".
const EventLogPrefix = "eventlog:"

// TailEventLog ships a Windows Event Log channel. A channel that does not
// exist yet (Sysmon not installed) or can't be read is retried with backoff.
func TailEventLog(path, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
	channel := strings.TrimPrefix(path, EventLogPrefix)
	backoff := 5 * time.Second
	for {
		slog.Info("subscribing to event log", "channel", channel, "type", logType)
		err := winevent.Subscribe(channel, func(line string) {
			buf.Push(encode(logType, path, line))
		}, stopCh)
		select {
		case <-stopCh:
			return
		default:
		}
		if errors.Is(err, winevent.ErrUnsupported) {
			slog.Warn("ignoring event log source on a non-Windows host", "path", path)
			return
		}
		slog.Warn("event log subscription ended, retrying", "channel", channel, "err", err, "retry_in", backoff)
		select {
		case <-stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}
