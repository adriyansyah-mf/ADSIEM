package hygiene

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func Collect(agentID, hostname string) (*Report, error) {
	r := &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}

	collectOS(r)
	collectUptime(r)
	collectMemory(r)
	collectCPU(r)
	collectDisk(r)
	collectPorts(r)
	collectUsers(r)
	score(r)

	return r, nil
}

func collectOS(r *Report) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		r.OSName = runtime.GOOS
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if k, v, ok := strings.Cut(line, "="); ok {
			v = strings.Trim(v, `"`)
			switch k {
			case "NAME":
				r.OSName = v
			case "VERSION_ID":
				r.OSVersion = v
			}
		}
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Kernel = strings.TrimSpace(string(data))
	}
}

func collectUptime(r *Report) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		f, _ := strconv.ParseFloat(fields[0], 64)
		r.UptimeSecs = int64(f)
	}
}

func collectMemory(r *Report) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	var total, available int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseInt(fields[1], 10, 64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = kb / 1024
		case "MemAvailable":
			available = kb / 1024
		}
	}
	r.MemTotalMB = total
	r.MemUsedMB = total - available
}

func collectCPU(r *Report) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		r.CPUCount = runtime.NumCPU()
		return
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "processor") {
			count++
		}
	}
	if count == 0 {
		count = runtime.NumCPU()
	}
	r.CPUCount = count
}

func collectDisk(r *Report) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return
	}
	defer f.Close()

	skip := map[string]bool{
		"tmpfs": true, "devtmpfs": true, "devpts": true,
		"sysfs": true, "proc": true, "cgroup": true, "cgroup2": true,
		"overlay": true, "aufs": true, "squashfs": true,
	}

	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		fstype := fields[2]
		mount := fields[1]
		if skip[fstype] || seen[mount] {
			continue
		}
		seen[mount] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount, &stat); err != nil {
			continue
		}
		if stat.Blocks == 0 {
			continue
		}
		totalMB := int64(stat.Blocks) * int64(stat.Bsize) / (1024 * 1024)
		freeMB := int64(stat.Bfree) * int64(stat.Bsize) / (1024 * 1024)
		usedMB := totalMB - freeMB
		if totalMB < 10 {
			continue
		}
		pct := float64(usedMB) / float64(totalMB) * 100
		r.Disk = append(r.Disk, DiskPartition{
			Mount:   mount,
			TotalMB: totalMB,
			UsedMB:  usedMB,
			UsePct:  pct,
		})
	}
}

// parseProcNetTCP reads /proc/net/tcp or /proc/net/tcp6 and returns LISTEN ports.
func parseProcNetTCP(path, proto string) []OpenPort {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ports []OpenPort
	seen := map[int]bool{}
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		stateHex := fields[3]
		state, _ := strconv.ParseUint(stateHex, 16, 8)
		if state != 0x0A { // TCP_LISTEN
			continue
		}
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) < 2 {
			continue
		}
		portHex := parts[len(parts)-1]
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		if !seen[int(port)] {
			seen[int(port)] = true
			ports = append(ports, OpenPort{Port: int(port), Proto: proto, State: "LISTEN"})
		}
	}
	return ports
}

func collectPorts(r *Report) {
	r.OpenPorts = append(r.OpenPorts, parseProcNetTCP("/proc/net/tcp", "tcp")...)
	r.OpenPorts = append(r.OpenPorts, parseProcNetTCP("/proc/net/tcp6", "tcp6")...)
}

func collectUsers(r *Report) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		shell := parts[6]
		if shell == "/sbin/nologin" || shell == "/bin/false" || shell == "/usr/sbin/nologin" {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		r.Users = append(r.Users, LocalUser{Name: parts[0], Shell: shell, UID: uid})
	}
}

var riskyPorts = map[int]string{
	21:   "FTP (plaintext)",
	23:   "Telnet (plaintext)",
	25:   "SMTP open relay risk",
	135:  "MSRPC",
	139:  "NetBIOS",
	445:  "SMB",
	3389: "RDP exposed",
	5900: "VNC exposed",
}

func score(r *Report) {
	s := 100
	var issues []Issue

	// disk
	for _, d := range r.Disk {
		if d.UsePct >= 95 {
			s -= 25
			issues = append(issues, Issue{"critical", "disk", d.Mount + " is " + strconv.Itoa(int(d.UsePct)) + "% full"})
		} else if d.UsePct >= 85 {
			s -= 15
			issues = append(issues, Issue{"high", "disk", d.Mount + " is " + strconv.Itoa(int(d.UsePct)) + "% full"})
		} else if d.UsePct >= 75 {
			s -= 5
			issues = append(issues, Issue{"medium", "disk", d.Mount + " is " + strconv.Itoa(int(d.UsePct)) + "% full"})
		}
	}

	// memory
	if r.MemTotalMB > 0 {
		memPct := float64(r.MemUsedMB) / float64(r.MemTotalMB) * 100
		if memPct >= 95 {
			s -= 20
			issues = append(issues, Issue{"high", "memory", "Memory usage at " + strconv.Itoa(int(memPct)) + "%"})
		} else if memPct >= 85 {
			s -= 10
			issues = append(issues, Issue{"medium", "memory", "Memory usage at " + strconv.Itoa(int(memPct)) + "%"})
		}
	}

	// risky ports
	seen := map[int]bool{}
	for _, p := range r.OpenPorts {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		if desc, bad := riskyPorts[p.Port]; bad {
			s -= 15
			issues = append(issues, Issue{"high", "port", "Port " + strconv.Itoa(p.Port) + " open: " + desc})
		}
	}

	// too many open ports
	unique := len(seen)
	if unique > 30 {
		s -= 10
		issues = append(issues, Issue{"medium", "port", strconv.Itoa(unique) + " ports listening"})
	}

	if s < 0 {
		s = 0
	}
	r.Score = s
	r.Issues = issues
}
