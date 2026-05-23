package tailer

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

// Tail reads new lines from path and pushes them to buf.
// Seeks to end of file on first open (tail -f behavior).
// Retries if file is not found (handles log rotation).
// Stops when stopCh is closed.
func Tail(path, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
	var missCount int
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			// Log once per 5-minute window to avoid spam when file doesn't exist yet.
			if missCount == 0 {
				slog.Warn("cannot open log file, will retry silently", "path", path, "err", err)
			}
			missCount++
			if missCount >= 60 { // reset every 5 min (60 × 5s)
				missCount = 0
			}
			time.Sleep(5 * time.Second)
			continue
		}
		missCount = 0
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			time.Sleep(time.Second)
			continue
		}
		slog.Info("tailing", "path", path, "type", logType)
		reader := bufio.NewReader(f)
		for {
			select {
			case <-stopCh:
				f.Close()
				return
			default:
			}
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				line = strings.TrimRight(line, "\r\n")
				if line != "" {
					buf.Push(encode(logType, line))
				}
			}
			if err == io.EOF {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			if err != nil {
				slog.Error("tailer read error", "path", path, "err", err)
				break
			}
		}
		f.Close()
	}
}

func encode(logType, rawMessage string) string {
	return logType + "\x00" + rawMessage
}

func Decode(entry string) (logType, rawMessage string) {
	for i, c := range entry {
		if c == '\x00' {
			return entry[:i], entry[i+1:]
		}
	}
	return "unknown", entry
}
