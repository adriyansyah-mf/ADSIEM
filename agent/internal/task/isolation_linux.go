//go:build linux

// agent/internal/task/isolation_linux.go
package task

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
)

const isolateChain = "SIEM_ISOLATE"

func isolateHost(serverURL string) error {
	siemIP, err := resolveSIEMIP(serverURL)
	if err != nil {
		return fmt.Errorf("resolve SIEM IP: %w", err)
	}
	exec.Command("iptables", "-N", isolateChain).Run()
	exec.Command("iptables", "-F", isolateChain).Run()
	rules := [][]string{
		{"-A", isolateChain, "-i", "lo", "-j", "ACCEPT"},
		{"-A", isolateChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", isolateChain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", isolateChain, "-d", siemIP, "-j", "ACCEPT"},
		{"-A", isolateChain, "-s", siemIP, "-j", "ACCEPT"},
		{"-A", isolateChain, "-j", "DROP"},
	}
	for _, r := range rules {
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %s", r, out)
		}
	}
	insertJumpIfMissing("INPUT")
	insertJumpIfMissing("OUTPUT")
	return nil
}

func unisolateHost() error {
	exec.Command("iptables", "-D", "INPUT", "-j", isolateChain).Run()
	exec.Command("iptables", "-D", "OUTPUT", "-j", isolateChain).Run()
	exec.Command("iptables", "-F", isolateChain).Run()
	exec.Command("iptables", "-X", isolateChain).Run()
	return nil
}

func insertJumpIfMissing(chain string) {
	if exec.Command("iptables", "-C", chain, "-j", isolateChain).Run() == nil {
		return
	}
	exec.Command("iptables", "-I", chain, "1", "-j", isolateChain).Run()
}

func resolveSIEMIP(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("cannot resolve %s", host)
	}
	return addrs[0], nil
}
