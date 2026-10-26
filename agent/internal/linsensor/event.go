// Package linsensor streams Linux host telemetry that procexec (exec) and
// netwatch (network) do not cover: file writes, renames and deletes,
// kernel module loads, ptrace, privilege gains, memfd and fileless exec,
// and process exits. One eBPF object (bpf/linsensor.bpf.c) attaches to
// syscall and sched tracepoints; this package decodes its records,
// resolves paths and images through /proc, limits volume and pushes kv
// log lines.
package linsensor

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Event kinds; keep in sync with K_* in bpf/linsensor.bpf.c.
const (
	kindOpen         = 1
	kindRename       = 2
	kindUnlink       = 3
	kindModuleInit   = 4
	kindModuleFinit  = 5
	kindModuleDelete = 6
	kindPtrace       = 7
	kindSetID        = 8
	kindCapset       = 9
	kindMemfd        = 10
	kindExec         = 11
	kindFilelessExec = 12
	kindExit         = 13
)

// Log types, one decoder each in decoders/.
const (
	LogFile      = "linux_file_event"
	LogModule    = "linux_kernel_module"
	LogPtrace    = "linux_ptrace"
	LogPrivilege = "linux_privilege_change"
	LogMemfd     = "linux_memfd_create"
	LogFileless  = "linux_fileless_exec"
	LogExit      = "linux_process_exit"
)

const (
	atFDCWD    = -100
	oWronly    = 01
	oRdwr      = 02
	oCreat     = 0100
	oTrunc     = 01000
	atRemovDir = 0x200
	commLen    = 16
	pathLen    = 256
	recordSize = 88 + 4*pathLen
)

// rawEvent is struct sensor_event from bpf/linsensor.bpf.c.
type rawEvent struct {
	kind              uint32
	pid, tgid, ppid   uint32
	uid, euid         uint32
	dfd, dfd2         int32
	ret               int64
	arg0, arg1, arg2  uint64
	comm, path, path2 string
	dir, dir2         string // set by the kernel when path / path2 is relative
	ts                uint64
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func decodeRaw(b []byte) (rawEvent, bool) {
	if len(b) < recordSize {
		return rawEvent{}, false
	}
	le := binary.LittleEndian
	return rawEvent{
		ts:    le.Uint64(b[0:]),
		ret:   int64(le.Uint64(b[8:])),
		arg0:  le.Uint64(b[16:]),
		arg1:  le.Uint64(b[24:]),
		arg2:  le.Uint64(b[32:]),
		kind:  le.Uint32(b[40:]),
		pid:   le.Uint32(b[44:]),
		tgid:  le.Uint32(b[48:]),
		ppid:  le.Uint32(b[52:]),
		uid:   le.Uint32(b[56:]),
		euid:  le.Uint32(b[60:]),
		dfd:   int32(le.Uint32(b[64:])),
		dfd2:  int32(le.Uint32(b[68:])),
		comm:  cstr(b[72 : 72+commLen]),
		path:  cstr(b[88 : 88+pathLen]),
		path2: cstr(b[88+pathLen : 88+2*pathLen]),
		dir:   cstr(b[88+2*pathLen : 88+3*pathLen]),
		dir2:  cstr(b[88+3*pathLen : 88+4*pathLen]),
	}, true
}

// FileEvent is one successful file write, rename or delete, after path
// resolution and before any rate limiting.
type FileEvent struct {
	Time   time.Time
	Action string // create, write, rename, delete
	Path   string // the new name for a rename
	From   string // the old name for a rename
	PID    uint32 // thread group id
	PPID   uint32
	UID    uint32
	Image  string
	Comm   string
	Dir    bool // a directory was removed
}

// kv quotes a value for the decoder's key="value" grammar.
func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func identity(sb *strings.Builder, ev rawEvent, image string) {
	fmt.Fprintf(sb, ` Image=%s Comm=%s PID=%d PPID=%d User=%d EUID=%d`, kv(image), kv(ev.comm), ev.tgid, ev.ppid, ev.uid, ev.euid)
}

func (f FileEvent) line() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `action=%s TargetFilename=%s`, f.Action, kv(f.Path))
	if f.From != "" {
		fmt.Fprintf(&sb, ` SourceFilename=%s`, kv(f.From))
	}
	if f.Dir {
		sb.WriteString(` IsDirectory=true`)
	}
	fmt.Fprintf(&sb, ` Image=%s Comm=%s PID=%d PPID=%d User=%d`, kv(f.Image), kv(f.Comm), f.PID, f.PPID, f.UID)
	return sb.String()
}

var ptraceRequests = map[uint64]string{4: "poketext", 5: "pokedata", 6: "pokeuser", 13: "setregs", 16: "attach", 0x4206: "seize"}

var setIDCalls = map[uint64]string{1: "setuid", 2: "setreuid", 3: "setresuid", 4: "setgid", 5: "setregid", 6: "setresgid"}

// signedID renders a set*id argument; -1 means unchanged.
func signedID(v uint64) string {
	if uint32(v) == 0xffffffff {
		return "-1"
	}
	return fmt.Sprint(uint32(v))
}

func moduleLine(ev rawEvent, image string) string {
	var sb strings.Builder
	switch ev.kind {
	case kindModuleInit:
		fmt.Fprintf(&sb, `action=load_memory Size=%d Params=%s`, ev.arg0, kv(ev.path2))
	case kindModuleFinit:
		fmt.Fprintf(&sb, `action=load Module=%s Params=%s`, kv(ev.path), kv(ev.path2))
	default:
		fmt.Fprintf(&sb, `action=unload Module=%s`, kv(ev.path))
	}
	identity(&sb, ev, image)
	return sb.String()
}

func ptraceLine(ev rawEvent, image, targetImage string) string {
	var sb strings.Builder
	req := ptraceRequests[ev.arg0]
	if req == "" {
		req = fmt.Sprint(ev.arg0)
	}
	fmt.Fprintf(&sb, `action=%s TargetPID=%d TargetImage=%s`, req, ev.arg1, kv(targetImage))
	identity(&sb, ev, image)
	return sb.String()
}

func privilegeLine(ev rawEvent, image, parentImage string) string {
	var sb strings.Builder
	if ev.kind == kindCapset {
		fmt.Fprintf(&sb, `action=capset Effective=0x%x Permitted=0x%x`, ev.arg0, ev.arg1)
	} else {
		ids := []string{signedID(ev.arg1 & 0xffffffff)}
		switch ev.arg0 {
		case 2, 5:
			ids = append(ids, signedID(ev.arg1>>32))
		case 3, 6:
			ids = append(ids, signedID(ev.arg1>>32), signedID(ev.arg2))
		}
		fmt.Fprintf(&sb, `action=%s IDs=%s`, setIDCalls[ev.arg0], kv(strings.Join(ids, ",")))
	}
	identity(&sb, ev, image)
	fmt.Fprintf(&sb, ` ParentImage=%s`, kv(parentImage))
	return sb.String()
}

func memfdLine(ev rawEvent, image string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `MemfdName=%s Flags=0x%x`, kv(ev.path), ev.arg0)
	identity(&sb, ev, image)
	return sb.String()
}

func filelessLine(ev rawEvent, parentImage string) string {
	var sb strings.Builder
	// Image is the kernel's name for the executable (memfd:<name>, or the
	// deleted file's name); ExecPath is what was passed to exec.
	fmt.Fprintf(&sb, `Image=%s ExecPath=%s Links=%d Comm=%s PID=%d PPID=%d User=%d EUID=%d ParentImage=%s`,
		kv(ev.path), kv(ev.path2), ev.arg0, kv(ev.comm), ev.tgid, ev.ppid, ev.uid, ev.euid, kv(parentImage))
	return sb.String()
}

func exitLine(ev rawEvent, image string) string {
	code := ev.arg0
	var sb strings.Builder
	if sig := code & 0x7f; sig != 0 {
		fmt.Fprintf(&sb, `ExitCode=-1 Signal=%d`, sig)
	} else {
		fmt.Fprintf(&sb, `ExitCode=%d Signal=0`, (code>>8)&0xff)
	}
	identity(&sb, ev, image)
	return sb.String()
}
