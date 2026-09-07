package hardening

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var insecurePorts = map[int]string{
	21:   "FTP (unencrypted)",
	23:   "Telnet",
	512:  "rexec",
	513:  "rlogin",
	514:  "rsh",
	6000: "X11",
}

func checkFirewallActive() Check {
	const id = "net-firewall-active"
	const category = "network"
	const title = "A firewall service is active with at least a default policy"

	if out, err := exec.Command("firewall-cmd", "--state").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "running" {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "firewalld is running"}
		}
	}
	if out, err := exec.Command("ufw", "status").Output(); err == nil {
		if strings.Contains(string(out), "Status: active") {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "ufw is active"}
		}
	}
	if out, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		if strings.TrimSpace(string(out)) != "" {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "nftables has an active ruleset"}
		}
	}
	if out, err := exec.Command("iptables", "-S").Output(); err == nil {
		s := string(out)
		if strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-P INPUT REJECT") {
			return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "iptables INPUT policy is DROP/REJECT"}
		}
		if strings.TrimSpace(s) != "" {
			return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "iptables has rules but INPUT policy is not DROP/REJECT"}
		}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "no active firewall backend detected (firewalld/ufw/nftables/iptables)"}
}

func checkIPForwardDisabled(path string) Check {
	const id = "net-ip-forward-disabled"
	const category = "network"
	const title = "IPv4 forwarding is disabled"

	data, err := os.ReadFile(path)
	if err != nil {
		return Check{ID: id, Category: category, Title: title, Status: StatusNotApplicable, Detail: "cannot read ip_forward sysctl"}
	}
	val := strings.TrimSpace(string(data))
	if val == "0" {
		return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "net.ipv4.ip_forward=0"}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "net.ipv4.ip_forward=" + val + " (expected 0 unless this host is a designated router)"}
}

func checkNoLegacyServices(ports []PortInfo) Check {
	const id = "net-no-legacy-services"
	const category = "network"
	const title = "No legacy/insecure network services are listening"

	var found []string
	for _, p := range ports {
		name, bad := insecurePorts[p.Port]
		if !bad {
			continue
		}
		state := strings.ToLower(p.State)
		if state == "listen" || state == "listening" {
			found = append(found, name+" ("+strconv.Itoa(p.Port)+")")
		}
	}
	if len(found) > 0 {
		return Check{ID: id, Category: category, Title: title, Status: StatusFail, Detail: "listening: " + strings.Join(found, ", ")}
	}
	return Check{ID: id, Category: category, Title: title, Status: StatusPass, Detail: "no legacy/insecure services found among " + strconv.Itoa(len(ports)) + " open port(s)"}
}
