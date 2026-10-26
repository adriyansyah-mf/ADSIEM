//go:build linux

package prevent

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// The fanotify engine asks the kernel to hold every exec on the marked
// mounts until the agent answers (FAN_OPEN_EXEC_PERM). It decides hash
// rules, and all rules where the BPF LSM is not available.
//
// Every exec on the host waits on this code, so it fails open: the
// agent's own execs are answered on the reading goroutine, a full queue
// is answered "allow", and if the agent dies the kernel allows whatever
// is pending when the fanotify fd closes.

const (
	fanWorkers   = 4
	fanQueue     = 256
	maxHashBytes = 64 << 20
	remarkEvery  = time.Minute
	hashCacheMax = 20000
)

// Pseudo and special file systems hold no programs worth checking.
var skipFS = map[string]bool{
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true, "mqueue": true,
	"debugfs": true, "tracefs": true, "securityfs": true, "pstore": true, "bpf": true,
	"configfs": true, "fusectl": true, "hugetlbfs": true, "autofs": true, "binfmt_misc": true,
	"nsfs": true, "efivarfs": true, "rpc_pipefs": true, "selinuxfs": true, "devtmpfs": true,
}

type fanPolicy struct {
	p             *Policy
	kernelDecides bool // the LSM engine already enforces path/dir/parent
}

type fanEvent struct {
	fd  int32
	pid int32
}

type hashKey struct {
	dev, ino     uint64
	ctime, mtime int64
	size         int64
}

type fanEngine struct {
	fd     int      // for fanotify_mark
	file   *os.File // the same fd, non-blocking through the runtime poller, so Close wakes read
	self   int32
	report func(Decision)
	policy atomic.Pointer[fanPolicy]
	work   chan fanEvent
	stop   chan struct{}
	done   sync.WaitGroup

	cacheMu sync.Mutex
	cache   map[hashKey]string
	marked  map[string]bool

	failedOpen atomic.Int64
}

func startFanotifyLocal(report func(Decision)) (*fanEngine, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	e := &fanEngine{
		fd: fd, file: os.NewFile(uintptr(fd), "fanotify"), self: int32(os.Getpid()), report: report,
		work: make(chan fanEvent, fanQueue), stop: make(chan struct{}),
		cache: map[hashKey]string{}, marked: map[string]bool{},
	}
	if n := e.markMounts(); n == 0 {
		e.file.Close()
		return nil, fmt.Errorf("fanotify: no mount could be marked for FAN_OPEN_EXEC_PERM")
	}
	e.done.Add(fanWorkers + 2)
	for i := 0; i < fanWorkers; i++ {
		go e.worker()
	}
	go e.read()
	go e.remark()
	slog.Info("prevent: fanotify engine started", "mounts", len(e.marked))
	return e, nil
}

func (e *fanEngine) setPolicy(p *Policy, kernelDecides bool) {
	e.policy.Store(&fanPolicy{p: p, kernelDecides: kernelDecides})
}

func (e *fanEngine) close() {
	close(e.stop)
	e.file.Close() // wakes read; pending events are allowed by the kernel
	e.done.Wait()
}

// unescapeMount undoes mountinfo's octal escapes (\040 is a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (e *fanEngine) markMounts() int {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		left, right, ok := strings.Cut(sc.Text(), " - ")
		fields, rest := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 5 || len(rest) < 1 || skipFS[rest[0]] {
			continue
		}
		mp := unescapeMount(fields[4])
		if e.marked[mp] {
			continue
		}
		err := unix.FanotifyMark(e.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, mp)
		if err == nil {
			e.marked[mp] = true
		}
	}
	return len(e.marked)
}

// remark picks up file systems mounted after start.
func (e *fanEngine) remark() {
	defer e.done.Done()
	t := time.NewTicker(remarkEvery)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.markMounts()
			if n := e.failedOpen.Swap(0); n > 0 {
				slog.Warn("prevent: exec checks queue full, allowed unchecked", "allowed", n)
			}
		}
	}
}

func (e *fanEngine) respond(fd int32, allow bool) {
	r := uint32(unix.FAN_ALLOW)
	if !allow {
		r = unix.FAN_DENY
	}
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:], uint32(fd))
	binary.LittleEndian.PutUint32(b[4:], r)
	e.file.Write(b[:])
	unix.Close(int(fd))
}

func (e *fanEngine) read() {
	defer e.done.Done()
	defer close(e.work)
	buf := make([]byte, 64*1024)
	for {
		n, err := e.file.Read(buf)
		if err != nil {
			return // closed
		}
		for off := 0; off+24 <= n; {
			le := binary.LittleEndian
			evLen := int(le.Uint32(buf[off:]))
			mask := le.Uint64(buf[off+8:])
			ev := fanEvent{fd: int32(le.Uint32(buf[off+16:])), pid: int32(le.Uint32(buf[off+20:]))}
			if evLen < 24 {
				break
			}
			off += evLen
			if ev.fd < 0 {
				continue
			}
			if mask&unix.FAN_OPEN_EXEC_PERM == 0 {
				unix.Close(int(ev.fd))
				continue
			}
			if ev.pid == e.self {
				e.respond(ev.fd, true)
				continue
			}
			select {
			case e.work <- ev:
			default:
				e.failedOpen.Add(1)
				e.respond(ev.fd, true)
			}
		}
	}
}

func (e *fanEngine) worker() {
	defer e.done.Done()
	for ev := range e.work {
		e.respond(ev.fd, e.decide(ev))
	}
}

func procStatus(pid int32) (ppid, uid uint32, comm string) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, ":")
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			comm = v
		case "PPid":
			n, _ := strconv.ParseUint(v, 10, 32)
			ppid = uint32(n)
		case "Uid":
			n, _ := strconv.ParseUint(strings.Fields(v + " 0")[0], 10, 32)
			uid = uint32(n)
		}
	}
	return
}

// hashFD hashes the file behind an event fd, cached by inode and times.
func (e *fanEngine) hashFD(fd int32) (string, bool) {
	var st unix.Stat_t
	if err := unix.Fstat(int(fd), &st); err != nil || st.Size > maxHashBytes {
		return "", false
	}
	key := hashKey{dev: st.Dev, ino: st.Ino, ctime: st.Ctim.Nano(), mtime: st.Mtim.Nano(), size: st.Size}
	e.cacheMu.Lock()
	h, ok := e.cache[key]
	e.cacheMu.Unlock()
	if ok {
		return h, true
	}
	sum := sha256.New()
	buf := make([]byte, 256*1024)
	var off int64
	for {
		n, err := unix.Pread(int(fd), buf, off)
		if n > 0 {
			sum.Write(buf[:n])
			off += int64(n)
		}
		if err != nil {
			return "", false
		}
		if n == 0 {
			break
		}
	}
	h = hex.EncodeToString(sum.Sum(nil))
	e.cacheMu.Lock()
	if len(e.cache) >= hashCacheMax {
		e.cache = map[hashKey]string{}
	}
	e.cache[key] = h
	e.cacheMu.Unlock()
	return h, true
}

// decide returns whether the exec may go ahead.
func (e *fanEngine) decide(ev fanEvent) bool {
	pol := e.policy.Load()
	if pol == nil || len(pol.p.Rules) == 0 {
		return true
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", ev.fd))
	if err != nil {
		return true
	}
	parent, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", ev.pid))
	var digest string
	c := pol.p.Match(Exec{Path: path, Parent: parent, Hash: func() (string, bool) {
		h, ok := e.hashFD(ev.fd)
		digest = h
		return h, ok
	}}, pol.kernelDecides)
	if c == nil {
		return true
	}
	ppid, uid, comm := procStatus(ev.pid)
	e.report(Decision{
		Rule: c, Blocked: c.block, Engine: "fanotify", Path: path, Parent: parent, SHA256: digest,
		Comm: comm, PID: uint32(ev.pid), PPID: ppid, UID: uid,
	})
	return !c.block
}
