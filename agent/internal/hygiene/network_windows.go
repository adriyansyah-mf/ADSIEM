package hygiene

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const gaaFlagIncludeGateways = 0x80

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

func collectNetworkPlatform(n *NetworkInfo) {
	n.FQDN = computerName(windows.ComputerNameDnsFullyQualified)
	n.Domain = computerName(windows.ComputerNameDnsDomain)
	n.DefaultGateway, n.DNSServers = adapterGatewayAndDNS()
	n.Timezone = regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, "TimeZoneKeyName")
	n.Sessions = wtsSessions()
}

func computerName(kind uint32) string {
	size := uint32(256)
	buf := make([]uint16, size)
	if err := windows.GetComputerNameEx(kind, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// adapterGatewayAndDNS: the first default gateway and every DNS server of
// the adapters that are up.
func adapterGatewayAndDNS() (string, []string) {
	size := uint32(15 << 10)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, gaaFlagIncludeGateways, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return "", nil
		}
		buf = nil
	}
	if buf == nil {
		return "", nil
	}
	var gateway string
	var dns []string
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for g := a.FirstGatewayAddress; g != nil && gateway == ""; g = g.Next {
			if ip := g.Address.IP(); ip != nil && ip.To4() != nil {
				gateway = ip.String()
			}
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil && !isSiteLocalPlaceholder(ip) {
				dns = append(dns, ip.String())
			}
		}
	}
	return gateway, cleanList(dns)
}

// fec0:0:0:ffff::1-3 are Windows' unconfigured IPv6 DNS placeholders.
func isSiteLocalPlaceholder(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip[0] == 0xfe && ip[1] == 0xc0
}

const (
	wtsUserName      = 5
	wtsClientAddress = 14
	wtsActive        = 0
	wtsDisconnected  = 4
)

// wtsSessions lists the console and Remote Desktop sessions with a user.
func wtsSessions() []Session {
	var infos *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &infos, &count); err != nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(infos)))
	var out []Session
	for _, s := range unsafe.Slice(infos, count) {
		if s.State != wtsActive && s.State != wtsDisconnected {
			continue
		}
		user := wtsString(s.SessionID, wtsUserName)
		if user == "" {
			continue
		}
		sess := Session{User: user, Line: windows.UTF16PtrToString(s.WindowStationName), From: wtsClientIP(s.SessionID)}
		if s.State == wtsDisconnected {
			sess.Line += " (disconnected)"
		}
		out = append(out, sess)
	}
	return out
}

// wtsQuery returns a buffer the caller frees with wtsFree.
func wtsQuery(session uint32, class uintptr) (*byte, uint32, bool) {
	var buf *byte
	var n uint32
	ok, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), class,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	return buf, n, ok != 0 && buf != nil
}

func wtsFree(buf *byte) { windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf))) }

func wtsString(session uint32, class uintptr) string {
	buf, _, ok := wtsQuery(session, class)
	if !ok {
		return ""
	}
	defer wtsFree(buf)
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(buf)))
}

// WTS_CLIENT_ADDRESS: AddressFamily, then the address (IPv4 at bytes 2-5).
type wtsClientAddr struct {
	Family  uint32
	Address [20]byte
}

func wtsClientIP(session uint32) string {
	buf, n, ok := wtsQuery(session, wtsClientAddress)
	if !ok {
		return ""
	}
	defer wtsFree(buf)
	if n < uint32(unsafe.Sizeof(wtsClientAddr{})) {
		return ""
	}
	a := (*wtsClientAddr)(unsafe.Pointer(buf))
	switch a.Family {
	case windows.AF_INET:
		return net.IP(a.Address[2:6]).String()
	case windows.AF_INET6:
		return net.IP(a.Address[2:18]).String()
	}
	return ""
}
