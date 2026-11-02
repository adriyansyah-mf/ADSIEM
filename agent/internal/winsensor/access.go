package winsensor

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

// LogTypeAccess carries what Sysmon reports as process access (EventID 10,
// Sigma windows/process_access) and remote thread creation (EventID 8,
// windows/create_remote_thread): credential dumping and code injection.
const LogTypeAccess = "windows_etw_access"

// GroupAccess turns both off (etw disable list), GroupThread only remote threads.
const (
	GroupAccess = "access"
	GroupThread = "thread"
)

const (
	// Microsoft-Windows-Kernel-Audit-API-Calls: event 5 is a successful or
	// failed NtOpenProcess, logged in the caller (TargetProcessId,
	// DesiredAccess, ReturnCode).
	auditAPIProvider = "{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}"
	auditOpenProcess = 5
	// Kernel-Process ThreadStart, logged in the creating thread's process
	// (ProcessID is the process the thread runs in).
	threadStartEvent = 3
	threadKeyword    = 0x20
)

// Process access rights that matter: reading memory (lsass: credentials) and
// what injection needs (writing memory, creating a thread).
const (
	accessCreateThread = 0x0002
	accessVMOperation  = 0x0008
	accessVMRead       = 0x0010
	accessVMWrite      = 0x0020
)

const csrssPath = `C:\Windows\System32\csrss.exe`

// accessRepeat: the same source, target and access is reported once per
// window (system processes open others all the time).
const accessRepeat = 10 * time.Minute

type accessTracker struct {
	j    *processJoiner
	self uint32
	seen map[string]time.Time
}

func newAccessTracker(j *processJoiner, self uint32) *accessTracker {
	return &accessTracker{j: j, self: self, seen: map[string]time.Time{}}
}

func (a *accessTracker) first(key string, now time.Time) bool {
	if t, ok := a.seen[key]; ok && now.Sub(t) < accessRepeat {
		return false
	}
	if len(a.seen) > 20000 {
		a.seen = map[string]time.Time{}
	}
	a.seen[key] = now
	return true
}

func (a *accessTracker) skipSource(pid uint32) bool {
	return pid == 0 || pid == 4 || pid == a.self
}

// openProcess: a Sysmon 10 lookalike, only for memory reads of lsass and
// for rights that allow injection into another process.
func (a *accessTracker) openProcess(ev *etw.Event, now time.Time) string {
	if ev.ID != auditOpenProcess {
		return ""
	}
	src := ev.PID
	target, ok := number(ev, "TargetProcessId")
	if !ok || a.skipSource(src) || target == src || target == 0 || target == 4 {
		return ""
	}
	if rc, ok := number(ev, "ReturnCode"); ok && rc != 0 {
		return "" // refused: nothing was opened
	}
	access, ok := number(ev, "DesiredAccess")
	if !ok {
		return ""
	}
	targetImage, _ := a.j.owner(target)
	lsass := strings.EqualFold(filepath.Base(strings.ReplaceAll(targetImage, `\`, "/")), "lsass.exe")
	if !(lsass && access&accessVMRead != 0) && access&(accessVMWrite|accessCreateThread) == 0 {
		return ""
	}
	srcImage, srcUser := a.j.owner(src)
	// csrss opens every new process with full access (measured on the
	// Windows runner): one line per program started, never an attack.
	if strings.EqualFold(srcImage, csrssPath) {
		return ""
	}
	granted := fmt.Sprintf("0x%X", access)
	if !a.first("a|"+srcImage+"|"+targetImage+"|"+granted, now) {
		return ""
	}
	return line(10, [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Audit-API-Calls"},
		{"SourceProcessId", strconv.FormatUint(uint64(src), 10)}, {"SourceImage", srcImage}, {"SourceUser", srcUser},
		{"TargetProcessId", strconv.FormatUint(uint64(target), 10)}, {"TargetImage", targetImage},
		{"GrantedAccess", granted},
	})
}

// threadStart: a Sysmon 8 lookalike when a process starts a thread in
// another one. A new process's first thread is created by its parent (that
// is CreateProcess, not injection) and is left out, as Sysmon does.
func (a *accessTracker) threadStart(ev *etw.Event, now time.Time) string {
	if ev.ID != threadStartEvent {
		return ""
	}
	creator := ev.PID
	target, ok := number(ev, "ProcessID")
	if !ok || a.skipSource(creator) || target == creator || target == 0 || target == 4 {
		return ""
	}
	if a.isInitialThread(creator, target, now) {
		return ""
	}
	srcImage, srcUser := a.j.owner(creator)
	targetImage, _ := a.j.owner(target)
	if !a.first("t|"+srcImage+"|"+targetImage, now) {
		return ""
	}
	start, _ := ev.Get("Win32StartAddr")
	if start == "" {
		start, _ = ev.Get("StartAddr")
	}
	tid, _ := number(ev, "TThreadId")
	fields := [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Process"},
		{"SourceProcessId", strconv.FormatUint(uint64(creator), 10)}, {"SourceImage", srcImage}, {"SourceUser", srcUser},
		{"TargetProcessId", strconv.FormatUint(uint64(target), 10)}, {"TargetImage", targetImage},
		{"StartAddress", start},
	}
	if tid != 0 {
		fields = append(fields, [2]string{"NewThreadId", strconv.FormatUint(uint64(tid), 10)})
	}
	return line(8, fields)
}

// isInitialThread: target was started by creator moments ago.
func (a *accessTracker) isInitialThread(creator, target uint32, now time.Time) bool {
	for _, p := range []*process{a.j.pending[target], a.j.known[target]} {
		if p != nil && p.ppid == creator && now.Sub(p.started) < 30*time.Second {
			return true
		}
	}
	return false
}
