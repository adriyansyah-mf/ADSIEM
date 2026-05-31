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
// Handles log rotation by detecting inode change on EOF.
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
			if missCount == 0 {
				slog.Warn("cannot open log file, will retry silently", "path", path, "err", err)
			}
			missCount++
			if missCount >= 60 {
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

		openedFi, _ := f.Stat()
		reader := bufio.NewReaderSize(f, 65536)

		for {
			select {
			case <-stopCh:
				f.Close()
				return
			default:
			}

			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				// Strip trailing newline/carriage return
				for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
					line = line[:len(line)-1]
				}
				if line != "" {
					buf.Push(encode(logType, line))
				}
			}
			if err == nil {
				continue
			}
			if err != io.EOF {
				slog.Error("reader error", "path", path, "err", err)
				break
			}
			// EOF — check for log rotation before sleeping
			if pathFi, statErr := os.Stat(path); statErr == nil && openedFi != nil {
				if !os.SameFile(openedFi, pathFi) {
					slog.Info("log rotation detected, reopening", "path", path)
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
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
