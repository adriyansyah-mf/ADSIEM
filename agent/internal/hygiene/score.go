package hygiene

import (
	"sort"
	"strconv"
)

// Scoring is shared by every platform's collector: it works on the Report
// alone, plus platformIssues for checks only the platform can make.

var riskyPorts = map[int]string{
	21:   "FTP (plaintext)",
	23:   "Telnet (plaintext)",
	25:   "SMTP open relay risk",
	135:  "MSRPC",
	139:  "NetBIOS",
	445:  "SMB",
	3389: "RDP exposed",
	5900: "VNC exposed",
	// data stores and daemons that are meant for localhost or a private
	// network and are attacked within hours when reachable (the otakunesia
	// miner scanned the internet for Redis)
	2375:  "Docker API (no authentication)",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	5984:  "CouchDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

// portLabel names a listening socket for an issue: "3306 (mysqld on 0.0.0.0)".
func portLabel(p OpenPort) string {
	s := strconv.Itoa(p.Port)
	switch {
	case p.Process != "" && p.Addr != "":
		s += " (" + p.Process + " on " + p.Addr + ")"
	case p.Process != "":
		s += " (" + p.Process + ")"
	case p.Addr != "":
		s += " (on " + p.Addr + ")"
	}
	return s
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

	// risky ports: only where other hosts can reach them. A database or
	// telnet bound to 127.0.0.1 is not exposure.
	seen := map[int]bool{}
	exposed := map[int]OpenPort{}
	for _, p := range r.OpenPorts {
		seen[p.Port] = true
		if _, done := exposed[p.Port]; !done && p.Exposed() {
			exposed[p.Port] = p
		}
	}
	ports := make([]int, 0, len(exposed))
	for port := range exposed {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	for _, port := range ports {
		p := exposed[port]
		if baselinePorts[port] {
			// always listening on this OS (e.g. Windows RPC/SMB): exposure is the firewall's job
			s -= issuePenalty["low"]
			issues = append(issues, Issue{"low", "port", "Port " + portLabel(p) + " listening (" +
				riskyPorts[port] + ", OS default) — keep it blocked at the firewall"})
			continue
		}
		if desc, bad := riskyPorts[port]; bad {
			s -= 15
			issues = append(issues, Issue{"high", "port", "Port " + portLabel(p) + " reachable from the network: " + desc})
		}
	}

	// too many open ports
	unique := len(seen)
	if unique > 30 {
		s -= 10
		issues = append(issues, Issue{"medium", "port", strconv.Itoa(unique) + " ports listening"})
	}

	// platform posture checks: firewall, remote login, credentials, pending
	// reboot, automatic updates, protection (linux_posture.go, windows_posture.go)
	for _, is := range platformIssues(r) {
		s -= issuePenalty[is.Severity]
		issues = append(issues, is)
	}

	if s < 0 {
		s = 0
	}
	r.Score = s
	r.Issues = issues
}

var issuePenalty = map[string]int{"critical": 25, "high": 15, "medium": 5, "low": 2}
