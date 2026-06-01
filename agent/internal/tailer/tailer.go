package tailer

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

// Tail reads new lines from path and pushes them to buf.
// path may contain glob wildcards (*,?,[]) — in that case the newest
// matching file is tailed and the tailer switches to newer files as
// they appear (daily rotation).
// Stops when stopCh is closed.
func Tail(path, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
	if isGlob(path) {
		tailGlob(path, logType, buf, stopCh)
	} else {
		tailFixed(path, logType, buf, stopCh)
	}
}

func isGlob(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// resolveNewest returns the path of the most-recently-modified file
// matching the glob pattern, or "" if none match.
func resolveNewest(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	newest := ""
	var newestMod time.Time
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if fi.ModTime().After(newestMod) {
			newestMod = fi.ModTime()
			newest = m
		}
	}
	return newest
}

// tailGlob tails the newest file matching pattern. When a newer file
// appears (e.g. daily rotation at midnight), it closes the current file
// and starts reading the new one from the beginning.
func tailGlob(pattern, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
	// seenFiles tracks which files we've already opened so we know whether
	// to seek to EOF (avoid replay on startup) or start from the beginning
	// (new daily file we've never seen before).
	seenFiles := map[string]bool{}
	var missCount int

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		currentPath := resolveNewest(pattern)
		if currentPath == "" {
			if missCount == 0 {
				slog.Warn("no files match glob pattern, will retry", "pattern", pattern)
			}
			missCount = (missCount + 1) % 12
			time.Sleep(5 * time.Second)
			continue
		}
		missCount = 0

		f, err := os.Open(currentPath)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		// On first encounter of a file: seek to EOF to avoid replaying old data.
		// On subsequent new files (rotation): read from the beginning so we
		// capture everything written to the new daily log.
		if !seenFiles[currentPath] {
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				f.Close()
				time.Sleep(time.Second)
				continue
			}
		}
		seenFiles[currentPath] = true
		slog.Info("tailing", "path", currentPath, "type", logType)

		openedFi, _ := f.Stat()
		reader := bufio.NewReaderSize(f, 65536)

	inner:
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
			if err == nil {
				continue
			}
			if err != io.EOF {
				slog.Error("reader error", "path", currentPath, "err", err)
				f.Close()
				break inner
			}
			// EOF — check if a newer file has appeared (daily rotation)
			if newer := resolveNewest(pattern); newer != currentPath {
				slog.Info("newer log file detected, switching", "from", currentPath, "to", newer, "type", logType)
				f.Close()
				break inner
			}
			// Check same-path rotation (file renamed but same path reused)
			if pathFi, statErr := os.Stat(currentPath); statErr == nil && openedFi != nil {
				if !os.SameFile(openedFi, pathFi) {
					slog.Info("log rotation detected, reopening", "path", currentPath)
					f.Close()
					break inner
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// tailFixed tails a fixed (non-glob) path, handling log rotation via inode check.
func tailFixed(path, logType string, buf *buffer.Buffer, stopCh <-chan struct{}) {
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
				line = strings.TrimRight(line, "\r\n")
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
