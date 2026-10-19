//go:build linux

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
	collectPackages(r)
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

func collectPackages(r *Report) {
	if pkgs := parseDpkg("/var/lib/dpkg/status"); len(pkgs) > 0 {
		r.Packages = pkgs
		return
	}
	if pkgs := parseApk("/lib/apk/db/installed"); len(pkgs) > 0 {
		r.Packages = pkgs
		return
	}
}

func parseDpkg(path string) []InstalledPackage {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs []InstalledPackage
	var name, version, status string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			// only include installed packages
			if name != "" && version != "" && strings.Contains(status, "installed") {
				pkgs = append(pkgs, InstalledPackage{Name: name, Version: version, Source: "dpkg"})
			}
			name, version, status = "", "", ""
			continue
		}
		if k, v, ok := strings.Cut(line, ": "); ok {
			switch k {
			case "Package":
				name = v
			case "Version":
				version = v
			case "Status":
				status = v
			}
		}
	}
	if name != "" && version != "" && strings.Contains(status, "installed") {
		pkgs = append(pkgs, InstalledPackage{Name: name, Version: version, Source: "dpkg"})
	}
	if len(pkgs) > 1000 {
		pkgs = pkgs[:1000]
	}
	return pkgs
}

func parseApk(path string) []InstalledPackage {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs []InstalledPackage
	var name, version string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if name != "" && version != "" {
				pkgs = append(pkgs, InstalledPackage{Name: name, Version: version, Source: "apk"})
			}
			name, version = "", ""
			continue
		}
		if strings.HasPrefix(line, "P:") {
			name = line[2:]
		} else if strings.HasPrefix(line, "V:") {
			version = line[2:]
		}
	}
	if name != "" && version != "" {
		pkgs = append(pkgs, InstalledPackage{Name: name, Version: version, Source: "apk"})
	}
	if len(pkgs) > 1000 {
		pkgs = pkgs[:1000]
	}
	return pkgs
}

// Linux has no extra posture checks or OS-default ports yet.
func platformIssues(*Report) []Issue { return nil }

var baselinePorts = map[int]bool{}
