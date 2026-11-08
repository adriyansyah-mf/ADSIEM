//go:build linux

package webblock

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ownerMaxFDs  = 20000
	ownerBudget  = 200 * time.Millisecond
	ownerMaxRows = 200000
)

// clientProcess finds the process that owns the client end of a loopback
// connection. Best effort and bounded; (0, "") when unknown.
func clientProcess(remoteAddr string) (int, string) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, ""
	}
	ip := net.ParseIP(host)
	port, perr := strconv.Atoi(portStr)
	if ip == nil || perr != nil {
		return 0, ""
	}
	deadline := time.Now().Add(ownerBudget)
	var inode string
	if ip4 := ip.To4(); ip4 != nil {
		inode = socketInode("/proc/net/tcp", hexAddr(ip4), port)
		if inode == "" {
			mapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip4[0], ip4[1], ip4[2], ip4[3]}
			inode = socketInode("/proc/net/tcp6", hexAddr(mapped), port)
		}
	} else {
		inode = socketInode("/proc/net/tcp6", hexAddr(ip.To16()), port)
	}
	if inode == "" || inode == "0" {
		return 0, ""
	}
	pid := inodeOwner(inode, deadline)
	if pid == 0 {
		return 0, ""
	}
	name := ""
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		name = strings.TrimSpace(string(b))
	}
	return pid, name
}

// hexAddr formats an address like /proc/net/tcp: each 32-bit word in host
// (little-endian) byte order.
func hexAddr(ip net.IP) string {
	var sb strings.Builder
	for i := 0; i+4 <= len(ip); i += 4 {
		fmt.Fprintf(&sb, "%02X%02X%02X%02X", ip[i+3], ip[i+2], ip[i+1], ip[i])
	}
	return sb.String()
}

// socketInode returns the inode of the socket whose local address is
// addr:port in a /proc/net/tcp-format file.
func socketInode(file, addr string, port int) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	want := fmt.Sprintf("%s:%04X", addr, port)
	sc := bufio.NewScanner(f)
	for i := 0; sc.Scan() && i < ownerMaxRows; i++ {
		fields := strings.Fields(sc.Text())
		if len(fields) > 9 && fields[1] == want {
			return fields[9]
		}
	}
	return ""
}

// inodeOwner scans /proc/*/fd for the socket, stopping after ownerMaxFDs
// entries or the deadline.
func inodeOwner(inode string, deadline time.Time) int {
	target := "socket:[" + inode + "]"
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return 0
	}
	seen := 0
	for _, d := range dirs {
		if time.Now().After(deadline) {
			return 0
		}
		entries, err := os.ReadDir(d + "/fd")
		if err != nil {
			continue
		}
		for _, e := range entries {
			if seen++; seen > ownerMaxFDs {
				return 0
			}
			if l, err := os.Readlink(d + "/fd/" + e.Name()); err == nil && l == target {
				pid, _ := strconv.Atoi(filepath.Base(d))
				return pid
			}
		}
	}
	return 0
}
