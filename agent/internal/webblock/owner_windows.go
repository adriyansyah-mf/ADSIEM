//go:build windows

package webblock

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	maxTableBytes       = 4 << 20
)

// tcpTable returns the raw MIB_TCP(6)TABLE_OWNER_PID, capped at 4 MiB.
func tcpTable(family uint32) []byte {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0)
	for i := 0; i < 3 && size > 0 && size <= maxTableBytes; i++ {
		buf := make([]byte, size)
		ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), tcpTableOwnerPIDAll, 0)
		if ret == 0 {
			return buf
		}
		if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
	}
	return nil
}

// clientProcess finds the process owning the client end of a loopback
// connection; (0, "") when unknown.
func clientProcess(remoteAddr string) (int, string) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, ""
	}
	port, perr := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	if perr != nil || ip == nil {
		return 0, ""
	}
	// MIB_TCPROW_OWNER_PID (24 bytes) and MIB_TCP6ROW_OWNER_PID (56 bytes).
	family, rowSize, portOff, pidOff := uint32(windows.AF_INET), 24, 8, 20
	if ip.To4() == nil {
		family, rowSize, portOff, pidOff = windows.AF_INET6, 56, 20, 52
	}
	buf := tcpTable(family)
	if len(buf) < 4 {
		return 0, ""
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		raw := binary.LittleEndian.Uint32(buf[off+portOff:])
		if int(raw&0xff)<<8|int(raw>>8&0xff) != port {
			continue
		}
		pid := binary.LittleEndian.Uint32(buf[off+pidOff:])
		if pid == 0 {
			return 0, ""
		}
		return int(pid), processName(pid)
	}
	return 0, ""
}

func processName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:size]))
}
