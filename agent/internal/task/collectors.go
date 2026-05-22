// agent/internal/task/collectors.go
package task

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ─── Process List ────────────────────────────────────────────────

type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	State   string `json:"state"`
	UID     string `json:"uid"`
	VmRSSKB string `json:"vmrss_kb"`
	Cmdline string `json:"cmdline"`
	Threads int    `json:"threads"`
}

func collectProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []ProcessInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		info := ProcessInfo{PID: pid}
		statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(statusBytes), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch k {
			case "Name":
				info.Name = v
			case "State":
				info.State = strings.Fields(v)[0]
			case "PPid":
				info.PPID, _ = strconv.Atoi(v)
			case "Uid":
				info.UID = strings.Fields(v)[0]
			case "VmRSS":
				info.VmRSSKB = strings.Fields(v)[0]
			case "Threads":
				info.Threads, _ = strconv.Atoi(v)
			}
		}
		cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		info.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmdlineBytes), "\x00", " "))
		procs = append(procs, info)
	}
	return procs, nil
}

// ─── Netstat ─────────────────────────────────────────────────────

type NetConn struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local"`
	RemoteAddr string `json:"remote"`
	State      string `json:"state"`
	PID        string `json:"pid"`
	Process    string `json:"process"`
}

func collectNetstat() (map[string]any, error) {
	out, err := exec.Command("ss", "-tulpn").Output()
	if err != nil {
		out, err = exec.Command("netstat", "-tulpn").Output()
	}
	var conns []NetConn
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			c := NetConn{Proto: fields[0], LocalAddr: fields[4]}
			if len(fields) > 5 {
				c.RemoteAddr = fields[5]
			}
			if len(fields) > 6 {
				c.State = fields[6]
			}
			if len(fields) > 7 {
				c.Process = fields[7]
			}
			conns = append(conns, c)
		}
	}
	// also parse /proc/net/tcp for established connections
	tcpConns := parseProcNetTCP()
	return map[string]any{
		"listening":    conns,
		"connections":  tcpConns,
		"raw":          string(out),
	}, nil
}

func parseProcNetTCP() []map[string]string {
	var result []map[string]string
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			state := tcpState(fields[3])
			if state == "LISTEN" || state == "ESTABLISHED" || state == "TIME_WAIT" {
				result = append(result, map[string]string{
					"local":  hexToAddr(fields[1]),
					"remote": hexToAddr(fields[2]),
					"state":  state,
				})
			}
		}
		file.Close()
	}
	return result
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

func tcpState(hex string) string {
	if s, ok := tcpStates[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}

func hexToAddr(hexAddr string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return hexAddr
	}
	ipHex, portHex := parts[0], parts[1]
	port, _ := strconv.ParseInt(portHex, 16, 32)
	// IPv4: little-endian 4 bytes
	if len(ipHex) == 8 {
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(ipHex[i*2:(i+1)*2], 16, 8)
			b[3-i] = byte(v)
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], port)
	}
	return fmt.Sprintf("[%s]:%d", ipHex, port)
}

// ─── File List ───────────────────────────────────────────────────

type FileEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

func collectFileList(path string, maxDepth int) ([]FileEntry, error) {
	var entries []FileEntry
	walkDir(path, path, 0, maxDepth, &entries)
	return entries, nil
}

func walkDir(root, current string, depth, maxDepth int, out *[]FileEntry) {
	if depth > maxDepth {
		return
	}
	dirEntries, err := os.ReadDir(current)
	if err != nil {
		return
	}
	for _, e := range dirEntries {
		fullPath := filepath.Join(current, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		*out = append(*out, FileEntry{
			Name:    e.Name(),
			Path:    fullPath,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
			IsDir:   e.IsDir(),
		})
		if e.IsDir() && depth < maxDepth {
			walkDir(root, fullPath, depth+1, maxDepth, out)
		}
	}
}

// ─── File Get ────────────────────────────────────────────────────

type FileContent struct {
	Path     string `json:"path"`
	SizeB    int64  `json:"size_bytes"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Truncated bool  `json:"truncated"`
}

const maxFileGetSize = 10 * 1024 * 1024 // 10 MB

func collectFileGet(path string) (FileContent, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileContent{}, err
	}
	if info.IsDir() {
		return FileContent{}, fmt.Errorf("path is a directory, use file_list")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return FileContent{}, err
	}
	truncated := false
	if len(data) > maxFileGetSize {
		data = data[:maxFileGetSize]
		truncated = true
	}
	return FileContent{
		Path:      path,
		SizeB:     info.Size(),
		Encoding:  "base64",
		Content:   base64.StdEncoding.EncodeToString(data),
		Truncated: truncated,
	}, nil
}

// ─── Persistence Check ───────────────────────────────────────────

type PersistenceItem struct {
	Category string `json:"category"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Exists   bool   `json:"exists"`
}

func collectPersistenceCheck() ([]PersistenceItem, error) {
	checks := []struct {
		category string
		globs    []string
	}{
		{"crontab", []string{"/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*"}},
		{"init_scripts", []string{"/etc/init.d/*", "/etc/rc.local", "/etc/rc.d/rc.local"}},
		{"systemd_units", []string{"/etc/systemd/system/*.service", "/lib/systemd/system/*.service"}},
		{"profile_scripts", []string{"/etc/profile", "/etc/profile.d/*.sh", "/root/.bashrc", "/root/.bash_profile", "/root/.profile"}},
		{"ssh_authorized_keys", []string{"/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"}},
		{"sudoers", []string{"/etc/sudoers", "/etc/sudoers.d/*"}},
		{"at_jobs", []string{"/var/spool/at/*"}},
		{"passwd_shadow", []string{"/etc/passwd", "/etc/shadow"}},
	}

	var items []PersistenceItem
	for _, check := range checks {
		for _, pattern := range check.globs {
			matched, _ := filepath.Glob(pattern)
			for _, path := range matched {
				info, err := os.Stat(path)
				if err != nil || info.IsDir() {
					continue
				}
				data, err := os.ReadFile(path)
				content := ""
				if err == nil {
					s := string(data)
					if len(s) > 4096 {
						s = s[:4096] + "\n... [truncated]"
					}
					content = s
				}
				items = append(items, PersistenceItem{
					Category: check.category,
					Path:     path,
					Content:  content,
					Exists:   err == nil,
				})
			}
		}
	}
	return items, nil
}

// ─── Users List ──────────────────────────────────────────────────

type UserEntry struct {
	Username string `json:"username"`
	UID      string `json:"uid"`
	GID      string `json:"gid"`
	Info     string `json:"info"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

func collectUsersList() ([]UserEntry, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var users []UserEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		users = append(users, UserEntry{
			Username: parts[0],
			UID:      parts[2],
			GID:      parts[3],
			Info:     parts[4],
			HomeDir:  parts[5],
			Shell:    parts[6],
		})
	}
	return users, nil
}

// ─── Dmesg Tail ──────────────────────────────────────────────────

func collectDmesgTail(lines int) (map[string]any, error) {
	out, err := exec.Command("dmesg", "-T", "--level=err,warn,crit,alert,emerg").Output()
	if err != nil {
		// fallback: read /var/log/kern.log
		data, ferr := os.ReadFile("/var/log/kern.log")
		if ferr != nil {
			return map[string]any{"raw": "", "error": err.Error()}, nil
		}
		out = data
	}
	logLines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(logLines) > lines {
		logLines = logLines[len(logLines)-lines:]
	}
	return map[string]any{"lines": logLines, "count": len(logLines)}, nil
}

// ─── Open Files ──────────────────────────────────────────────────

type OpenFile struct {
	PID     int    `json:"pid"`
	Process string `json:"process"`
	FD      string `json:"fd"`
	Path    string `json:"path"`
}

func collectOpenFiles(limit int) ([]OpenFile, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var result []OpenFile
	for _, e := range entries {
		if len(result) >= limit {
			break
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		name := procName(pid)
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || strings.HasPrefix(link, "socket:") || strings.HasPrefix(link, "pipe:") {
				continue
			}
			result = append(result, OpenFile{PID: pid, Process: name, FD: fd.Name(), Path: link})
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func procName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}
