package ioa

import (
	"net"
	"strconv"
	"strings"
)

// Kind is what an event is about.
type Kind uint8

const (
	KindProc   Kind = 1 << iota // a process started
	KindNet                     // an outbound connection
	KindFile                    // a file created, written or renamed into place
	KindAccess                  // another process's memory opened, read or written (or ptrace)
	KindThread                  // a thread created in another process
	KindPriv                    // a set*id / capset call (Linux)
)

// Event is one sensor line, the same shape on Linux and Windows.
type Event struct {
	Kind        Kind
	PID, PPID   uint32
	Image       string // the acting process; the new process for KindProc
	CommandLine string
	ParentImage string
	User        string
	// KindNet
	DestIP   string
	DestPort int
	Public   bool // not private, loopback, link-local or unspecified
	// KindFile
	Path string
	// KindAccess / KindThread
	TargetPID   uint32
	TargetImage string
	Access      uint32 // Windows GrantedAccess
	// KindAccess / KindPriv: vm_read, attach, setuid, ...
	Action string
	IDs    string // KindPriv: the ids asked for
}

// Log types the engine reads (agent/internal/winsensor, procexec, netwatch,
// linsensor).
var logTypes = map[string]bool{
	"windows_etw_process": true, "windows_etw_network": true, "windows_etw_file": true,
	"windows_etw_access": true,
	"linux_process_exec": true, "linux_network_connect": true, "linux_file_event": true,
	"linux_process_access": true, "linux_ptrace": true, "linux_privilege_change": true,
}

// Wanted reports whether the engine reads lines of logType.
func Wanted(logType string) bool { return logTypes[logType] }

// fields parses key=value and key="value" pairs as the server does
// (worker/decoder_engine.py _parse_kv): inside quotes \" is a quote and \\ a
// backslash; any other backslash is literal, so C:\Windows stays as is.
func fields(line string) map[string]string {
	out := make(map[string]string, 16)
	i, n := 0, len(line)
	for i < n {
		for i < n && line[i] == ' ' {
			i++
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= n || line[i] != '=' {
			continue // a bare word: skip it
		}
		key := line[start:i]
		i++
		var val string
		if i < n && line[i] == '"' {
			i++
			var b strings.Builder
			for i < n && line[i] != '"' {
				if line[i] == '\\' && i+1 < n && (line[i+1] == '"' || line[i+1] == '\\') {
					i++
				}
				b.WriteByte(line[i])
				i++
			}
			i++ // closing quote
			val = b.String()
		} else {
			s := i
			for i < n && line[i] != ' ' {
				i++
			}
			val = line[s:i]
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

func u32(s string) uint32 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// public: a routable address (not private, loopback, link-local, multicast
// or unspecified).
func public(ip string) bool {
	a := net.ParseIP(strings.Trim(ip, "[]"))
	if a == nil {
		return false
	}
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast())
}

// normalize turns one sensor line into an Event; ok is false for lines the
// engine does not use.
func normalize(logType, line string) (Event, bool) {
	f := fields(line)
	switch logType {
	case "windows_etw_process":
		if f["EventID"] != "1" {
			return Event{}, false
		}
		return Event{Kind: KindProc, PID: u32(f["ProcessId"]), PPID: u32(f["ParentProcessId"]), Image: f["Image"],
			CommandLine: f["CommandLine"], ParentImage: f["ParentImage"], User: f["User"]}, true
	case "linux_process_exec":
		return Event{Kind: KindProc, PID: u32(f["PID"]), PPID: u32(f["PPID"]), Image: f["Image"],
			CommandLine: f["CommandLine"], ParentImage: f["ParentImage"], User: f["User"]}, true
	case "windows_etw_network":
		if f["EventID"] != "3" || f["Initiated"] != "true" {
			return Event{}, false
		}
		port, _ := strconv.Atoi(f["DestinationPort"])
		return Event{Kind: KindNet, PID: u32(f["ProcessId"]), Image: f["Image"], User: f["User"],
			DestIP: f["DestinationIp"], DestPort: port, Public: public(f["DestinationIp"])}, true
	case "linux_network_connect":
		pid := u32(f["tgid"])
		if pid == 0 {
			pid = u32(f["pid"])
		}
		port, _ := strconv.Atoi(f["dport"])
		return Event{Kind: KindNet, PID: pid, Image: f["comm"], User: f["uid"],
			DestIP: f["dst"], DestPort: port, Public: public(f["dst"])}, true
	case "windows_etw_file":
		if f["EventID"] != "11" {
			return Event{}, false // 23: a delete
		}
		switch f["FileAction"] {
		case "create", "write", "rename", "":
		default:
			return Event{}, false
		}
		return Event{Kind: KindFile, PID: u32(f["ProcessId"]), Image: f["Image"], User: f["User"],
			Path: f["TargetFilename"], Action: f["FileAction"]}, true
	case "linux_file_event":
		switch f["action"] {
		case "create", "write", "rename":
		default:
			return Event{}, false
		}
		return Event{Kind: KindFile, PID: u32(f["PID"]), PPID: u32(f["PPID"]), Image: f["Image"], User: f["User"],
			Path: f["TargetFilename"], Action: f["action"]}, true
	case "windows_etw_access":
		ev := Event{PID: u32(f["SourceProcessId"]), Image: f["SourceImage"], User: f["SourceUser"],
			TargetPID: u32(f["TargetProcessId"]), TargetImage: f["TargetImage"]}
		switch f["EventID"] {
		case "10":
			ev.Kind, ev.Access, ev.Action = KindAccess, u32(f["GrantedAccess"]), "open"
		case "8":
			ev.Kind, ev.Action = KindThread, "remote_thread"
		default:
			return Event{}, false
		}
		return ev, true
	case "linux_process_access", "linux_ptrace":
		return Event{Kind: KindAccess, PID: u32(f["PID"]), PPID: u32(f["PPID"]), Image: f["Image"], User: f["User"],
			TargetPID: u32(f["TargetPID"]), TargetImage: f["TargetImage"], Action: f["action"]}, true
	case "linux_privilege_change":
		return Event{Kind: KindPriv, PID: u32(f["PID"]), PPID: u32(f["PPID"]), Image: f["Image"], User: f["User"],
			ParentImage: f["ParentImage"], Action: f["action"], IDs: f["IDs"]}, true
	}
	return Event{}, false
}
