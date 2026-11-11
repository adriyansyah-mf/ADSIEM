//go:build linux

package credwatch

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Watcher marks the credential stores of every login user with fanotify
// (FAN_OPEN, notification only: nothing waits on the agent) and reports
// opens by programs that do not own them.
type Watcher struct {
	file   *os.File
	fd     int
	push   func(logType, line string)
	self   int32
	lim    *Limiter
	homes  func() []string
	mu     sync.Mutex
	marked map[string]bool
	stop   chan struct{}
	wg     sync.WaitGroup
}

// Start marks the stores and reports until Stop. push sends one line.
func Start(push func(logType, line string)) (*Watcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify: %w", err)
	}
	w := &Watcher{file: os.NewFile(uintptr(fd), "credwatch-fanotify"), fd: fd, push: push, self: int32(os.Getpid()),
		lim: NewLimiter(0), homes: func() []string { return Homes("/etc/passwd") }, marked: map[string]bool{},
		stop: make(chan struct{})}
	n := w.mark()
	slog.Info("credential store watch started", "marks", n)
	w.wg.Add(2)
	go w.read()
	go w.rescan()
	return w, nil
}

// mark adds a mark on every target not marked yet; the count marked.
func (w *Watcher) mark() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, h := range w.homes() {
		for _, t := range Targets(h) {
			if w.marked[t.Path] {
				continue
			}
			mask := uint64(unix.FAN_OPEN)
			if t.Dir {
				mask |= unix.FAN_EVENT_ON_CHILD
			}
			if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, t.Path); err != nil {
				slog.Debug("credwatch: mark failed", "path", t.Path, "err", err)
				continue
			}
			w.marked[t.Path] = true
		}
	}
	return len(w.marked)
}

// rescan picks up new users, browser profiles and wallets.
func (w *Watcher) rescan() {
	defer w.wg.Done()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.mark()
		}
	}
}

func (w *Watcher) read() {
	defer w.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		n, err := w.file.Read(buf)
		if err != nil {
			return // closed
		}
		for off := 0; off+24 <= n; {
			le := binary.LittleEndian
			evLen := int(le.Uint32(buf[off:]))
			fd := int32(le.Uint32(buf[off+16:]))
			pid := int32(le.Uint32(buf[off+20:]))
			if evLen < 24 {
				break
			}
			off += evLen
			if fd < 0 {
				continue
			}
			path, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
			unix.Close(int(fd))
			if pid == w.self || path == "" {
				continue
			}
			w.report(pid, path)
		}
	}
}

// report sends one line for an open of path by pid, unless the store's
// owner opened it or (pid, kind) was reported recently.
func (w *Watcher) report(pid int32, path string) {
	kind, ok := Classify(path)
	if !ok || !w.lim.Allow(uint32(pid), kind) {
		return
	}
	image, _ := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	image = strings.TrimSuffix(image, " (deleted)")
	ppid, uid := procStatus(pid)
	if image == "" {
		if b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/comm"); err == nil {
			image = strings.TrimSpace(string(b))
		}
	}
	if Expected(kind, image) {
		return
	}
	w.push(LogType, Line(kind, path, image, uint32(pid), ppid, uid))
}

func procStatus(pid int32) (ppid uint32, uid string) {
	f, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/status")
	if err != nil {
		return 0, ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "PPid:"):
			v, _ := strconv.ParseUint(strings.TrimSpace(line[5:]), 10, 32)
			ppid = uint32(v)
		case strings.HasPrefix(line, "Uid:"):
			if f := strings.Fields(line[4:]); len(f) > 0 {
				uid = f[0]
			}
		}
	}
	return ppid, uid
}

// Stop ends the watch.
func (w *Watcher) Stop() {
	close(w.stop)
	w.file.Close()
	w.wg.Wait()
}
