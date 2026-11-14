//go:build linux

package hygiene

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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
	collectNetwork(r, time.Now())
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

// parseProcNetTCP reads /proc/net/tcp or /proc/net/tcp6 and returns the
// LISTEN sockets with their bound address, and each one's socket inode.
func parseProcNetTCP(path, proto string) ([]OpenPort, []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	return parseListen(f, proto)
}

func parseListen(r io.Reader, proto string) ([]OpenPort, []string) {
	var ports []OpenPort
	var inodes []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Scan() // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		state, _ := strconv.ParseUint(fields[3], 16, 8)
		if state != 0x0A { // TCP_LISTEN
			continue
		}
		addrHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		addr := procNetAddr(addrHex)
		key := addr + "|" + portHex
		if seen[key] {
			continue
		}
		seen[key] = true
		ports = append(ports, OpenPort{Port: int(port), Proto: proto, State: "LISTEN", Addr: addr})
		inodes = append(inodes, fields[9])
	}
	return ports, inodes
}

// procNetAddr decodes /proc/net/tcp{,6} addresses: 32-bit words in host
// (little-endian) order.
func procNetAddr(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return ""
	}
	ip := make(net.IP, len(b))
	for w := 0; w < len(b); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	return ip.String()
}

// socketOwners maps socket inodes to the name of a process holding them.
func socketOwners(want map[string]bool) map[string]string {
	owners := map[string]string{}
	if len(want) == 0 {
		return owners
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + p.Name() + "/fd")
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + p.Name() + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if !want[inode] || owners[inode] != "" {
				continue
			}
			if comm == "" {
				c, _ := os.ReadFile("/proc/" + p.Name() + "/comm")
				comm = strings.TrimSpace(string(c))
			}
			owners[inode] = comm
		}
		if len(owners) == len(want) {
			break
		}
	}
	return owners
}

func collectPorts(r *Report) {
	v4, i4 := parseProcNetTCP("/proc/net/tcp", "tcp")
	v6, i6 := parseProcNetTCP("/proc/net/tcp6", "tcp6")
	ports, inodes := append(v4, v6...), append(i4, i6...)
	want := map[string]bool{}
	for _, in := range inodes {
		if in != "0" {
			want[in] = true
		}
	}
	owners := socketOwners(want)
	for i := range ports {
		ports[i].Process = owners[inodes[i]]
	}
	r.OpenPorts = ports
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
	// RHEL, Rocky, Alma, Fedora, SUSE: the rpm database is not a text file
	if out, err := runTimeout("rpm", "-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}\n`); err == nil {
		r.Packages = parseRpmQuery(out)
	}
}

// parseRpmQuery reads `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`.
func parseRpmQuery(out string) []InstalledPackage {
	var pkgs []InstalledPackage
	for _, line := range strings.Split(out, "\n") {
		name, version, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" || version == "" || name == "gpg-pubkey" {
			continue
		}
		pkgs = append(pkgs, InstalledPackage{Name: name, Version: version, Source: "rpm"})
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	if len(pkgs) > 1000 {
		pkgs = pkgs[:1000]
	}
	return pkgs
}

// runTimeout runs a system tool for the posture checks, bounded so a hung
// tool cannot stall the report.
func runTimeout(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
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

// platformIssues runs the Linux posture checks (linux_posture.go) on this host.
func platformIssues(r *Report) []Issue {
	return linuxPosture(linuxHost{
		readFile: func(p string) (string, error) {
			b, err := os.ReadFile(p)
			return string(b), err
		},
		glob: func(p string) []string {
			m, _ := filepath.Glob(p)
			return m
		},
		exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		run: runTimeout,
	}, r)
}

var baselinePorts = map[int]bool{}
