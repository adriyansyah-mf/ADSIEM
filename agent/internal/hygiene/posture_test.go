package hygiene

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHost struct {
	files map[string]string
	cmds  map[string]string // "name args" -> output; missing = not installed
}

func (f fakeHost) host() linuxHost {
	return linuxHost{
		readFile: func(p string) (string, error) {
			if s, ok := f.files[p]; ok {
				return s, nil
			}
			return "", errors.New("missing")
		},
		glob: func(pattern string) []string {
			var out []string
			for p := range f.files {
				if ok, _ := filepath.Match(pattern, p); ok {
					out = append(out, p)
				}
			}
			return out
		},
		exists: func(p string) bool {
			if _, ok := f.files[p]; ok {
				return true
			}
			for k := range f.files {
				if strings.HasPrefix(k, p+"/") {
					return true
				}
			}
			_, ok := f.cmds[p]
			return ok
		},
		run: func(name string, args ...string) (string, error) {
			if out, ok := f.cmds[strings.Join(append([]string{name}, args...), " ")]; ok {
				return out, nil
			}
			return "", errors.New("not found")
		},
	}
}

func categories(issues []Issue) map[string]string {
	m := map[string]string{}
	for _, is := range issues {
		m[is.Category+":"+firstWord(is.Message)] = is.Severity
	}
	return m
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// otakunesia on 2026-11-14 scored 100 with no issues while root could log in
// over SSH with a password, no firewall was on and a reboot was pending.
func TestLinuxPostureOnACompromisedHost(t *testing.T) {
	h := fakeHost{
		files: map[string]string{
			"/etc/ufw/ufw.conf":                       "ENABLED=no\n",
			"/etc/passwd":                             "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\ntoor:x:0:0::/root:/bin/sh\ndev:x:1000:1000::/home/dev:/bin/bash\n",
			"/etc/shadow":                             "root:$6$x:1:0:::::\nwww-data:*:1::::::\ntoor:$6$y:1::::::\ndev::1::::::\n",
			"/etc/sudoers":                            "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n# deploy ALL=(ALL) NOPASSWD: ALL\n",
			"/etc/sudoers.d/90-cloud":                 "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
			"/etc/sudoers.d/README":                   "x NOPASSWD: ALL\n",
			"/etc/sudoers.d/old.bak":                  "y NOPASSWD: ALL\n",
			"/var/run/reboot-required":                "*** System restart required ***\n",
			"/var/run/reboot-required.pkgs":           "linux-image-7.0.0-23-generic\nlinux-base\n",
			"/etc/apt/apt.conf.d/20auto-upgrades":     "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
			"/sys/module/apparmor/parameters/enabled": "Y\n",
		},
		cmds: map[string]string{
			"/usr/sbin/sshd":                "",
			"/usr/sbin/sshd -T":             "port 22\npermitrootlogin yes\npasswordauthentication yes\n",
			"systemctl is-active firewalld": "inactive\n",
			// only the agent's own table hooks input
			"nft list ruleset":  "table inet siem_ioc {\n\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n\t}\n}\n",
			"iptables -S INPUT": "-P INPUT ACCEPT\n",
		},
	}
	got := categories(linuxPosture(h.host(), &Report{}))
	want := map[string]string{
		"firewall:No":     "high",
		"ssh:SSH":         "high",
		"privilege:sudo":  "medium",
		"user:Accounts":   "high", // dev has no password (toor's UID 0 is reported separately)
		"patch:A":         "medium",
		"patch:Automatic": "medium",
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("%s: got %q, want %q (all: %v)", k, got[k], sev, got)
		}
	}
	issues := linuxPosture(h.host(), &Report{})
	var uid0, sudo, reboot bool
	for _, is := range issues {
		switch {
		case strings.Contains(is.Message, "UID 0: toor"):
			uid0 = is.Severity == "critical"
		case strings.HasPrefix(is.Message, "sudo without a password for: ubuntu") && !strings.Contains(is.Message, "x,"):
			sudo = !strings.Contains(is.Message, "deploy") && !strings.Contains(is.Message, " y")
		case strings.Contains(is.Message, "linux-image-7.0.0-23-generic"):
			reboot = true
		}
		if is.Category == "protection" {
			t.Errorf("AppArmor is enforcing: %v", is)
		}
	}
	if !uid0 || !sudo || !reboot {
		t.Errorf("uid0=%v sudo=%v reboot=%v: %v", uid0, sudo, reboot, issues)
	}
}

func TestLinuxPostureOnAHardenedHost(t *testing.T) {
	h := fakeHost{
		files: map[string]string{
			"/etc/passwd":                         "root:x:0:0:root:/root:/bin/bash\n",
			"/etc/shadow":                         "root:!:1::::::\n",
			"/etc/sudoers":                        "root ALL=(ALL:ALL) ALL\n",
			"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n",
			"/sys/fs/selinux/enforce":             "1",
		},
		cmds: map[string]string{
			"/usr/sbin/sshd":    "",
			"/usr/sbin/sshd -T": "permitrootlogin prohibit-password\npasswordauthentication no\n",
			"nft list ruleset":  "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n",
		},
	}
	r := &Report{Packages: []InstalledPackage{{Name: "unattended-upgrades"}}}
	if issues := linuxPosture(h.host(), r); len(issues) != 0 {
		t.Fatalf("a hardened host has no issues: %v", issues)
	}
}

func TestSshdConfigFilesWhenSshdTFails(t *testing.T) {
	h := fakeHost{files: map[string]string{
		"/etc/ssh/sshd_config":                 "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n#PasswordAuthentication no\nMatch User bob\n  PasswordAuthentication no\n",
		"/etc/ssh/sshd_config.d/50-cloud.conf": "PasswordAuthentication no\n",
	}, cmds: map[string]string{"/usr/sbin/sshd": ""}}
	root, pass, ok := sshdSettings(h.host())
	if !ok || root != "yes" || pass != "no" {
		t.Fatalf("root=%q pass=%q ok=%v: the included file comes first, Match blocks do not count", root, pass, ok)
	}
	h = fakeHost{files: map[string]string{"/etc/ssh/sshd_config": "Port 22\n"}, cmds: map[string]string{"/usr/sbin/sshd": ""}}
	if root, pass, _ := sshdSettings(h.host()); root != "prohibit-password" || pass != "yes" {
		t.Fatalf("defaults: root=%q pass=%q", root, pass)
	}
	if _, _, ok := sshdSettings(fakeHost{}.host()); ok {
		t.Fatal("no sshd installed: no opinion")
	}
}

func TestFirewallDetection(t *testing.T) {
	if !iptablesInputDrops("-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n") ||
		!iptablesInputDrops("-P INPUT ACCEPT\n-A INPUT -j ufw-before-input\n") ||
		iptablesInputDrops("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n") {
		t.Fatal("iptables")
	}
	if nftInputDrops("table ip siem_isolation {\n chain input { type filter hook input priority 0; policy drop; }\n}\n") {
		t.Fatal("the agent's own isolation table is not the host's firewall")
	}
	h := fakeHost{files: map[string]string{"/etc/ufw/ufw.conf": "# comment\nENABLED=yes\n"}}
	if !linuxFirewallActive(h.host()) {
		t.Fatal("ufw enabled")
	}
	h = fakeHost{cmds: map[string]string{"systemctl is-active firewalld": "active\n"}}
	if !linuxFirewallActive(h.host()) {
		t.Fatal("firewalld")
	}
}

func TestPortsAreRiskyOnlyWhenReachable(t *testing.T) {
	r := &Report{OpenPorts: []OpenPort{
		{Port: 6379, Proto: "tcp", Addr: "127.0.0.1", Process: "redis-server"},
		{Port: 6379, Proto: "tcp6", Addr: "::1", Process: "redis-server"},
		{Port: 3306, Proto: "tcp", Addr: "0.0.0.0", Process: "mysqld"},
		{Port: 23, Proto: "tcp", Addr: "127.0.0.1"},
		{Port: 27017, Proto: "tcp"}, // address unknown (older agent): exposed
		{Port: 22, Proto: "tcp", Addr: "0.0.0.0", Process: "sshd"},
	}}
	score(r)
	var msgs []string
	for _, is := range r.Issues {
		if is.Category == "port" {
			msgs = append(msgs, is.Message)
		}
	}
	joined := strings.Join(msgs, "|")
	if len(msgs) != 2 || !strings.Contains(joined, "3306 (mysqld on 0.0.0.0) reachable from the network: MySQL") ||
		!strings.Contains(joined, "27017 reachable") {
		t.Fatalf("port issues: %v", msgs)
	}
}

type fakeReg struct {
	dwords map[string]uint64
	strs   map[string]string
	bins   map[string][]byte
	keys   map[string]bool
}

func (f fakeReg) dword(p, n string) (uint64, bool) { v, ok := f.dwords[p+`\`+n]; return v, ok }
func (f fakeReg) str(p, n string) string           { return f.strs[p+`\`+n] }
func (f fakeReg) binary(p, n string) []byte        { return f.bins[p+`\`+n] }
func (f fakeReg) exists(p string) bool             { return f.keys[p] }

func filetime(t time.Time) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(t.UnixNano()/100)+116444736000000000)
	return b
}

func TestWindowsPosture(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	bad := fakeReg{
		dwords: map[string]uint64{
			`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall`: 0,
			`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`:                         1,
			`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate`:                                     1,
			`SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`:                                   0,
			`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`:               0,
		},
		strs: map[string]string{
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon`:  "1",
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword`: "hunter2",
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultUserName`: "kiosk",
		},
		bins: map[string][]byte{
			`SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignaturesLastUpdated`: filetime(now.Add(-30 * 24 * time.Hour)),
		},
		keys: map[string]bool{`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`: true},
	}
	got := windowsPosture(bad, now, true)
	text := ""
	for _, is := range got {
		text += is.Severity + " " + is.Category + ": " + is.Message + "\n"
	}
	for _, want := range []string{
		"high firewall: Windows Firewall is off for the public profile",
		"high credentials: WDigest",
		"high credentials: Automatic logon stores the password of kiosk",
		"high rdp:",
		"medium patch: A reboot is pending",
		"medium patch: Automatic updates are turned off",
		"medium antivirus: Microsoft Defender signatures are 30 days old",
		"medium user: The Guest account is enabled",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	// Defender passive behind another antivirus: its signatures are not ours to judge
	bad.dwords[`SOFTWARE\Microsoft\Windows Defender\PassiveMode`] = 1
	for _, is := range windowsPosture(bad, now, false) {
		if strings.Contains(is.Message, "signatures") {
			t.Errorf("passive Defender: %v", is)
		}
	}
	fresh := fakeReg{bins: map[string][]byte{
		`SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignaturesLastUpdated`: filetime(now.Add(-time.Hour)),
	}}
	if got := windowsPosture(fresh, now, false); len(got) != 0 {
		t.Fatalf("a clean host has no issues: %v", got)
	}
}
