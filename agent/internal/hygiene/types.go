package hygiene

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

type Report struct {
	AgentID     string          `json:"agent_id"`
	Hostname    string          `json:"hostname"`
	OSName      string          `json:"os_name"`
	OSVersion   string          `json:"os_version"`
	Kernel      string          `json:"kernel"`
	Arch        string          `json:"arch"`
	UptimeSecs  int64           `json:"uptime_seconds"`
	CPUCount    int             `json:"cpu_count"`
	MemTotalMB  int64           `json:"mem_total_mb"`
	MemUsedMB   int64           `json:"mem_used_mb"`
	Disk        []DiskPartition `json:"disk_partitions"`
	OpenPorts   []OpenPort      `json:"open_ports"`
	Users       []LocalUser     `json:"users"`
	Score       int             `json:"hygiene_score"`
	Issues      []Issue         `json:"issues"`
	CollectedAt string          `json:"collected_at"`
}
