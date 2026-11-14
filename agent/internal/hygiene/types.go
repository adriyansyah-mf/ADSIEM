package hygiene

import "net"

type DiskPartition struct {
	Mount   string  `json:"mount"`
	TotalMB int64   `json:"total_mb"`
	UsedMB  int64   `json:"used_mb"`
	UsePct  float64 `json:"use_pct"`
}

type OpenPort struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	State string `json:"state"`
	// Addr is the address the socket is bound to (0.0.0.0, ::, 127.0.0.1, a
	// host address); Process the program listening on it, when known.
	Addr    string `json:"addr,omitempty"`
	Process string `json:"process,omitempty"`
}

// Exposed reports whether the port is reachable from other hosts: bound to
// anything but loopback. An unknown address counts as exposed.
func (p OpenPort) Exposed() bool {
	if p.Addr == "" {
		return true
	}
	ip := net.ParseIP(p.Addr)
	return ip == nil || !ip.IsLoopback()
}

type LocalUser struct {
	Name  string `json:"name"`
	Shell string `json:"shell"`
	UID   int    `json:"uid"`
}

type Issue struct {
	Severity string `json:"severity"` // critical/high/medium/low
	Category string `json:"category"` // disk/memory/port/user
	Message  string `json:"message"`
}

type InstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // dpkg, apk, rpm
}

type Report struct {
	AgentID     string             `json:"agent_id"`
	Hostname    string             `json:"hostname"`
	OSName      string             `json:"os_name"`
	OSVersion   string             `json:"os_version"`
	Kernel      string             `json:"kernel"`
	Arch        string             `json:"arch"`
	UptimeSecs  int64              `json:"uptime_seconds"`
	CPUCount    int                `json:"cpu_count"`
	MemTotalMB  int64              `json:"mem_total_mb"`
	MemUsedMB   int64              `json:"mem_used_mb"`
	Disk        []DiskPartition    `json:"disk_partitions"`
	OpenPorts   []OpenPort         `json:"open_ports"`
	Users       []LocalUser        `json:"users"`
	Packages    []InstalledPackage `json:"packages"`
	Score       int                `json:"hygiene_score"`
	Issues      []Issue            `json:"issues"`
	CollectedAt string             `json:"collected_at"`
	// Network is who the host is on the network and who is logged in: what
	// an analyst needs to turn an IP in an alert into this host.
	Network *NetworkInfo `json:"network,omitempty"`
}

type NetInterface struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac,omitempty"`
	Addrs []string `json:"addrs"` // CIDR: 10.0.0.5/24, fe80::1/64
	Up    bool     `json:"up"`
}

// Session is a logged-in user: a terminal, SSH, console or RDP session.
type Session struct {
	User  string `json:"user"`
	Line  string `json:"line,omitempty"`  // pts/0, tty1, RDP-Tcp#3, Console
	From  string `json:"from,omitempty"`  // remote address or host
	Since string `json:"since,omitempty"` // RFC 3339
}

type NetworkInfo struct {
	FQDN           string         `json:"fqdn,omitempty"`
	Domain         string         `json:"domain,omitempty"`
	Interfaces     []NetInterface `json:"interfaces,omitempty"`
	DefaultGateway string         `json:"default_gateway,omitempty"`
	DNSServers     []string       `json:"dns_servers,omitempty"`
	Timezone       string         `json:"timezone,omitempty"`   // Asia/Jakarta, SE Asia Standard Time
	UTCOffset      string         `json:"utc_offset,omitempty"` // +07:00
	BootTime       string         `json:"boot_time,omitempty"`
	Sessions       []Session      `json:"sessions,omitempty"`
}
