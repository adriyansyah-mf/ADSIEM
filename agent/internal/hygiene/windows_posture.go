package hygiene

// Windows security posture from the registry. Plain functions over a registry
// reader so they are tested on any OS; the Windows collector passes the real
// registry (collector_windows.go). Severities match the Linux checks for the
// same risk (linux_posture.go).

import (
	"encoding/binary"
	"strconv"
	"time"
)

// winRegistry reads HKLM.
type winRegistry interface {
	dword(path, name string) (uint64, bool)
	str(path, name string) string
	binary(path, name string) []byte
	exists(path string) bool
}

const defenderStaleAfter = 7 * 24 * time.Hour

func windowsPosture(reg winRegistry, now time.Time, guestEnabled bool) []Issue {
	var issues []Issue
	add := func(sev, cat, msg string) { issues = append(issues, Issue{sev, cat, msg}) }

	const fw = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	for _, p := range []struct{ key, label string }{
		{"DomainProfile", "domain"}, {"StandardProfile", "private"}, {"PublicProfile", "public"},
	} {
		if v, ok := reg.dword(fw+p.key, "EnableFirewall"); ok && v == 0 {
			add("high", "firewall", "Windows Firewall is off for the "+p.label+" profile")
		}
	}

	const defender = `SOFTWARE\Microsoft\Windows Defender`
	realtimeOff := false
	if v, ok := reg.dword(defender+`\Real-Time Protection`, "DisableRealtimeMonitoring"); ok && v == 1 {
		realtimeOff = true
		add("high", "antivirus", "Microsoft Defender real-time protection is disabled")
	}
	// Signatures: only when Defender is the active antivirus (not passive
	// behind another product, real-time on).
	if passive, _ := reg.dword(defender, "PassiveMode"); passive != 1 && !realtimeOff {
		if b := reg.binary(defender+`\Signature Updates`, "SignaturesLastUpdated"); len(b) == 8 {
			// FILETIME: 100 ns intervals since 1601-01-01
			const unixEpoch = 116444736000000000
			if ft := binary.LittleEndian.Uint64(b); ft > unixEpoch {
				updated := time.Unix(0, 0).Add(time.Duration(ft-unixEpoch) * 100)
				if age := now.Sub(updated); age > defenderStaleAfter {
					add("medium", "antivirus", "Microsoft Defender signatures are "+strconv.Itoa(int(age.Hours()/24))+" days old")
				}
			}
		}
	}

	if v, ok := reg.dword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"); ok && v == 0 {
		add("high", "uac", "User Account Control (UAC) is disabled")
	}
	if v, ok := reg.dword(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); ok && v == 1 {
		add("medium", "smb", "SMBv1 server is enabled")
	}
	if guestEnabled {
		add("medium", "user", "The Guest account is enabled")
	}
	if v, ok := reg.dword(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"); ok && v == 0 {
		if nla, ok := reg.dword(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
			"UserAuthentication"); ok && nla == 0 {
			add("high", "rdp", "Remote Desktop is enabled without Network Level Authentication")
		}
	}

	// Credentials kept where anyone with admin or a memory dump reads them.
	if v, ok := reg.dword(`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential"); ok && v == 1 {
		add("high", "credentials", "WDigest keeps logon passwords in memory in clear text (UseLogonCredential=1)")
	}
	const winlogon = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	if reg.str(winlogon, "AutoAdminLogon") == "1" && reg.str(winlogon, "DefaultPassword") != "" {
		add("high", "credentials", "Automatic logon stores the password of "+orUnknown(reg.str(winlogon, "DefaultUserName"))+
			" in the registry (AutoAdminLogon)")
	}

	if reg.exists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) ||
		reg.exists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		add("medium", "patch", "A reboot is pending: installed updates are not running yet")
	}
	const au = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	if v, ok := reg.dword(au, "NoAutoUpdate"); ok && v == 1 {
		add("medium", "patch", "Automatic updates are turned off by policy (NoAutoUpdate)")
	}
	return issues
}

func orUnknown(s string) string {
	if s == "" {
		return "an account"
	}
	return s
}
