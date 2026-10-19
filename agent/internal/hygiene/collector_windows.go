//go:build windows

package hygiene

import (
	"encoding/binary"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Collect gathers the same report as on Linux from Win32 APIs and the registry
// (no PowerShell/WMI: those are slow, and their text output is localized).
func Collect(agentID, hostname string) (*Report, error) {
	r := &Report{
		AgentID:     agentID,
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		CPUCount:    runtime.NumCPU(),
		UptimeSecs:  uptimeSeconds(),
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}
	collectOSWindows(r)
	collectMemoryWindows(r)
	collectDiskWindows(r)
	r.OpenPorts = listeningPorts()
	r.Users = localUsers()
	r.Packages = installedPrograms()
	score(r)
	return r, nil
}

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// regDword returns the value and whether it exists.
func regDword(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

func collectOSWindows(r *Report) {
	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	product := regString(registry.LOCAL_MACHINE, cv, "ProductName")
	build := regString(registry.LOCAL_MACHINE, cv, "CurrentBuild")
	ubr, _ := regDword(registry.LOCAL_MACHINE, cv, "UBR")
	// Windows 11 still reports "Windows 10 ..." as ProductName; the build tells them apart.
	if b, _ := strconv.Atoi(build); b >= 22000 && strings.Contains(product, "Windows 10") {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	r.OSName = product
	r.OSVersion = regString(registry.LOCAL_MACHINE, cv, "DisplayVersion") // e.g. 23H2
	if r.OSVersion == "" {
		r.OSVersion = regString(registry.LOCAL_MACHINE, cv, "ReleaseId")
	}
	r.Kernel = "10.0." + build + "." + strconv.FormatUint(ubr, 10)
}

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

func uptimeSeconds() int64 {
	ms, _, _ := procGetTickCount64.Call()
	return int64(ms / 1000)
}

// MEMORYSTATUSEX
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func collectMemoryWindows(r *Report) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	if ok, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); ok != 0 {
		r.MemTotalMB = int64(m.TotalPhys / (1024 * 1024))
		r.MemUsedMB = int64((m.TotalPhys - m.AvailPhys) / (1024 * 1024))
	}
}

func collectDiskWindows(r *Report) {
	buf := make([]uint16, 256)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || n == 0 {
		return
	}
	for _, root := range strings.Split(windows.UTF16ToString(buf[:n]), "\x00") {
		if root == "" {
			continue
		}
		p, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree) != nil || total == 0 {
			continue
		}
		used := total - totalFree
		r.Disk = append(r.Disk, DiskPartition{
			Mount:   strings.TrimSuffix(root, `\`),
			TotalMB: int64(total / (1024 * 1024)),
			UsedMB:  int64(used / (1024 * 1024)),
			UsePct:  float64(used) / float64(total) * 100,
		})
	}
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	netapi32                = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum         = netapi32.NewProc("NetUserEnum")
)

const tcpTableOwnerPIDListener = 3

// tcpListenTable returns the raw MIB_TCP(6)TABLE_OWNER_PID of listening sockets.
func tcpListenTable(family uint32) []byte {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDListener, 0)
	for i := 0; i < 3 && size > 0; i++ {
		buf := make([]byte, size)
		ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), tcpTableOwnerPIDListener, 0)
		if ret == 0 {
			return buf
		}
		if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
	}
	return nil
}

func listeningPorts() []OpenPort {
	var ports []OpenPort
	for _, t := range []struct {
		family  uint32
		proto   string
		rowSize int
		portOff int // offset of dwLocalPort in the row
	}{
		{windows.AF_INET, "tcp", 24, 8},   // MIB_TCPROW_OWNER_PID
		{windows.AF_INET6, "tcp6", 56, 20}, // MIB_TCP6ROW_OWNER_PID
	} {
		buf := tcpListenTable(t.family)
		if len(buf) < 4 {
			continue
		}
		n := int(binary.LittleEndian.Uint32(buf[:4]))
		for i := 0; i < n; i++ {
			off := 4 + i*t.rowSize
			if off+t.rowSize > len(buf) {
				break
			}
			raw := binary.LittleEndian.Uint32(buf[off+t.portOff:])
			port := int(raw&0xff)<<8 | int(raw>>8&0xff) // network byte order in the low 16 bits
			ports = append(ports, OpenPort{Port: port, Proto: t.proto, State: "LISTEN"})
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports
}

// USER_INFO_1
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

const (
	ufAccountDisable = 0x0002
	userPrivAdmin    = 2
	filterNormal     = 0x0002 // FILTER_NORMAL_ACCOUNT
)

// guestEnabled is set by localUsers for platformIssues.
var guestEnabled bool

// localUsers lists enabled local accounts. LocalUser.Shell carries the
// privilege level ("administrator"/"user"), Windows having no login shell.
func localUsers() []LocalUser {
	var buf *byte
	var read, total, resume uint32
	ret, _, _ := procNetUserEnum.Call(0, 1, filterNormal, uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if ret != 0 || buf == nil {
		return nil
	}
	defer windows.NetApiBufferFree(buf)
	guestEnabled = false
	entries := unsafe.Slice((*userInfo1)(unsafe.Pointer(buf)), read)
	var users []LocalUser
	for _, u := range entries {
		name := windows.UTF16PtrToString(u.Name)
		if u.Flags&ufAccountDisable != 0 {
			continue
		}
		if strings.EqualFold(name, "Guest") {
			guestEnabled = true
		}
		priv := "user"
		if u.Priv == userPrivAdmin {
			priv = "administrator"
		}
		users = append(users, LocalUser{Name: name, Shell: priv})
	}
	return users
}

// installedPrograms reads Add/Remove Programs (machine-wide, 64- and 32-bit views).
func installedPrograms() []InstalledPackage {
	seen := map[string]bool{}
	var pkgs []InstalledPackage
	for _, path := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sub := range names {
			full := path + `\` + sub
			name := regString(registry.LOCAL_MACHINE, full, "DisplayName")
			if name == "" {
				continue
			}
			if v, ok := regDword(registry.LOCAL_MACHINE, full, "SystemComponent"); ok && v == 1 {
				continue
			}
			if regString(registry.LOCAL_MACHINE, full, "ParentKeyName") != "" { // an update of another entry
				continue
			}
			version := regString(registry.LOCAL_MACHINE, full, "DisplayVersion")
			if seen[name+"\x00"+version] {
				continue
			}
			seen[name+"\x00"+version] = true
			pkgs = append(pkgs, InstalledPackage{Name: name, Version: version, Source: "windows"})
		}
	}
	sort.Slice(pkgs, func(i, j int) bool { return strings.ToLower(pkgs[i].Name) < strings.ToLower(pkgs[j].Name) })
	if len(pkgs) > 1000 {
		pkgs = pkgs[:1000]
	}
	return pkgs
}

// RPC endpoint mapper, NetBIOS and SMB listen on every Windows host.
var baselinePorts = map[int]bool{135: true, 139: true, 445: true}

// platformIssues checks the Windows security baseline the detections rely on.
func platformIssues(r *Report) []Issue {
	var issues []Issue
	const fw = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	for _, p := range []struct{ key, label string }{
		{"DomainProfile", "domain"}, {"StandardProfile", "private"}, {"PublicProfile", "public"},
	} {
		if v, ok := regDword(registry.LOCAL_MACHINE, fw+p.key, "EnableFirewall"); ok && v == 0 {
			issues = append(issues, Issue{"high", "firewall", "Windows Firewall is off for the " + p.label + " profile"})
		}
	}
	if v, ok := regDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`,
		"DisableRealtimeMonitoring"); ok && v == 1 {
		issues = append(issues, Issue{"high", "antivirus", "Microsoft Defender real-time protection is disabled"})
	}
	if v, ok := regDword(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"EnableLUA"); ok && v == 0 {
		issues = append(issues, Issue{"high", "uac", "User Account Control (UAC) is disabled"})
	}
	if v, ok := regDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
		"SMB1"); ok && v == 1 {
		issues = append(issues, Issue{"medium", "smb", "SMBv1 server is enabled"})
	}
	if guestEnabled {
		issues = append(issues, Issue{"medium", "user", "The Guest account is enabled"})
	}
	if v, ok := regDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"fDenyTSConnections"); ok && v == 0 {
		if nla, ok := regDword(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication"); ok && nla == 0 {
			issues = append(issues, Issue{"high", "rdp", "Remote Desktop is enabled without Network Level Authentication"})
		}
	}
	return issues
}
