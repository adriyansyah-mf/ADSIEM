package tailer

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

// Tail reads new lines from path and pushes them to buf.
// Seeks to end of file on first open (tail -f behavior).
// Retries if file is not found (handles log rotation).
// Stops when stopCh is closed.
func Tail(path, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			slog.Warn("cannot open log file", "path", path, "err", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			time.Sleep(time.Second)
			continue
		}
		slog.Info("tailing", "path", path, "type", logType)
		scanner := bufio.NewScanner(f)
		for {
			select {
			case <-stopCh:
				f.Close()
				return
			default:
			}
			if scanner.Scan() {
				line := scanner.Text()
				if line != "" {
					buf.Push(encode(logType, line))
				}
			} else {
				if scanner.Err() != nil {
					slog.Error("scanner error", "path", path, "err", scanner.Err())
					break
				}
				time.Sleep(200 * time.Millisecond)
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
