package hygiene

import "strconv"

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
		if baselinePorts[p.Port] {
			// always listening on this OS (e.g. Windows RPC/SMB): exposure is the firewall's job
			s -= issuePenalty["low"]
			issues = append(issues, Issue{"low", "port", "Port " + strconv.Itoa(p.Port) + " listening (" +
				riskyPorts[p.Port] + ", OS default) — keep it blocked at the firewall"})
			continue
		}
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

	// platform posture checks (firewall, AV, ...) — none on Linux yet
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
