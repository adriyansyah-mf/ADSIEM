package ioa

import (
	"fmt"
	"strings"
	"time"
)

// Rule is an ordered chain of steps. Step 0 anchors the rule at the process
// it happened in; each later step must come from that process or one under
// it (or, Keyed, name the file an earlier step captured), within Window of
// the anchor.
type Rule struct {
	ID        string
	Title     string
	Severity  string // medium, high, critical
	Tactic    string
	Technique string
	OS        string // windows, linux, "" for both
	Window    time.Duration
	Steps     []Step
}

// Step is one link of a chain.
type Step struct {
	Name  string
	Kinds Kind
	// Match decides on the event; p is the acting process (for KindProc the
	// new process: p.parent is its parent).
	Match func(ev *Event, p *proc) bool
	// Narrow: later tree steps must come from this step's process (or one
	// under it), not anywhere under the anchor.
	Narrow bool
	// Capture names the file the next (Keyed) step must be about.
	Capture func(ev *Event) string
	// Keyed: matched by the captured file (a process started from it),
	// whichever process it comes from.
	Keyed bool
}

// ─── matching helpers ────────────────────────────────────────────────

// baseName is the lower-cased file name of a Windows or Linux path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// in: the program's file name is in m. Linux names often carry a version
// (php-fpm8.2, python3.11): a name in m ending in "*" matches as a prefix.
func in(m map[string]bool, path string) bool {
	b := baseName(path)
	if m[b] {
		return true
	}
	for k := range m {
		if strings.HasSuffix(k, "*") && strings.HasPrefix(b, k[:len(k)-1]) {
			return true
		}
	}
	return false
}

func hasAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func parentImage(ev *Event, p *proc) string {
	if ev.ParentImage != "" {
		return ev.ParentImage
	}
	if p != nil && p.parent != nil {
		return p.parent.image
	}
	return ""
}

var (
	officeApps = set("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe",
		"visio.exe", "msaccess.exe", "eqnedt32.exe", "wordpad.exe")
	// script hosts and binaries attackers run instead of their own (LOLBins)
	winLaunchers = set("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
		"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
		"regasm.exe", "regsvcs.exe", "msiexec.exe", "wmic.exe", "forfiles.exe", "hh.exe", "cmstp.exe",
		"curl.exe", "schtasks.exe", "msxsl.exe", "odbcconf.exe")
	winScriptHosts = set("wscript.exe", "cscript.exe", "mshta.exe")
	winShells      = set("cmd.exe", "powershell.exe", "pwsh.exe")
	shells         = set("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox")
	webServers     = set("w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "tomcat.exe", "tomcat8.exe",
		"tomcat9.exe", "tomcat10.exe", "httpd", "apache2", "nginx", "lighttpd", "php-fpm*", "php-cgi*", "caddy",
		"uwsgi")
	reconTools = set("whoami.exe", "systeminfo.exe", "ipconfig.exe", "net.exe", "net1.exe", "nltest.exe",
		"quser.exe", "query.exe", "tasklist.exe", "hostname.exe", "netstat.exe", "arp.exe", "route.exe",
		"dsquery.exe", "klist.exe", "id", "whoami", "uname", "hostname", "ifconfig", "netstat", "ss", "w",
		"last", "getent", "groups", "lsb_release")
	downloaders    = set("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "curl", "wget", "tftp", "ftp", "tftp.exe", "ftp.exe")
	reverseShellKW = []string{"/dev/tcp/", "/dev/udp/", "pty.spawn", "socket.socket", "fsockopen", "socat exec:",
		"exec:/bin/", "-e /bin/sh", "-e /bin/bash", "nc -e", "ncat -e", "net.sockets.tcpclient",
		"mkfifo /tmp/"}
	reverseShellImages = set("sh", "bash", "dash", "zsh", "ksh", "python*", "perl*", "php*",
		"ruby*", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "powershell.exe", "pwsh.exe",
		"lua", "awk", "gawk", "telnet")
	// encoded / hidden / download-and-run PowerShell
	psSuspicious = []string{" -enc", " -e ", " -ec ", "-encodedcommand", "frombase64string", "downloadstring",
		"downloadfile", "invoke-webrequest", "iwr ", "invoke-expression", "iex(", "iex (", "net.webclient",
		"-windowstyle hidden", "-w hidden", "bitstransfer", "start-bitstransfer"}
	execExts = []string{".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
		".js", ".jse", ".wsf", ".hta", ".msi", ".sys"}
)

// userWritable: a folder any user (or any program it runs) can write to,
// where installed software does not usually run from.
func userWritable(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	if len(l) >= 2 && l[1] == ':' {
		return hasAny(l, `\appdata\local\temp\`, `\appdata\roaming\`, `\downloads\`, `\users\public\`,
			`\windows\temp\`, `\$recycle.bin\`, `\perflogs\`, `\programdata\`) &&
			!hasAny(l, `\programdata\microsoft\windows defender\`, `\appdata\roaming\microsoft\teams\`)
	}
	return strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/dev/shm/") || strings.HasPrefix(p, "/var/tmp/") ||
		strings.HasPrefix(p, "/run/shm/")
}

func execFile(p string) bool {
	if len(p) >= 2 && p[1] == ':' {
		l := strings.ToLower(p)
		for _, x := range execExts {
			if strings.HasSuffix(l, x) {
				return true
			}
		}
		return false
	}
	return true // Linux: anything can be made executable
}

func lsass(p string) bool { return baseName(p) == "lsass.exe" }

const (
	procVMRead       = 0x0010
	procVMWrite      = 0x0020
	procCreateThread = 0x0002
	procVMOperation  = 0x0008
)

func path(ev *Event) string { return ev.Path }

// ─── the rules ───────────────────────────────────────────────────────

// Rules are the built-in chains. IDs are stable: the server has a Sigma
// rule per ID (rules/ioa_*.yaml).
func Rules() []*Rule {
	officeAnchor := Step{Name: "office app", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool { return in(officeApps, ev.Image) }}
	internet := func(name string) Step {
		return Step{Name: name, Kinds: KindNet, Match: func(ev *Event, _ *proc) bool { return ev.Public }}
	}
	return []*Rule{
		{
			ID: "ioa_office_child_internet", Title: "Office app started a script host that reached the internet",
			Severity: "high", Tactic: "initial-access", Technique: "T1566.001", OS: "windows", Window: 5 * time.Minute,
			Steps: []Step{
				officeAnchor,
				{Name: "child launcher", Kinds: KindProc, Narrow: true, Match: func(ev *Event, _ *proc) bool { return in(winLaunchers, ev.Image) }},
				internet("internet connection"),
			},
		},
		{
			ID: "ioa_office_drop_exec", Title: "Office app wrote a program that was then run",
			Severity: "high", Tactic: "execution", Technique: "T1204.002", OS: "windows", Window: 10 * time.Minute,
			Steps: []Step{
				officeAnchor,
				{Name: "dropped file", Kinds: KindFile, Capture: path, Match: func(ev *Event, _ *proc) bool {
					return execFile(ev.Path) && !strings.HasSuffix(strings.ToLower(ev.Path), ".tmp")
				}},
				{Name: "ran it", Kinds: KindProc, Keyed: true},
			},
		},
		{
			ID: "ioa_script_host_download_exec", Title: "Script host reached the internet and started a program",
			Severity: "high", Tactic: "execution", Technique: "T1059.005", OS: "windows", Window: 5 * time.Minute,
			Steps: []Step{
				{Name: "script host", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool {
					return in(winScriptHosts, ev.Image) && (userWritable(ev.CommandLine) || hasAny(ev.CommandLine, "http:", "https:", "javascript:", "vbscript:"))
				}},
				internet("internet connection"),
				{Name: "started", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool {
					return in(winLaunchers, ev.Image) || userWritable(ev.Image)
				}},
			},
		},
		{
			ID: "ioa_powershell_download_child", Title: "Obfuscated or download PowerShell reached the internet and started a program",
			Severity: "medium", Tactic: "execution", Technique: "T1059.001", OS: "windows", Window: 5 * time.Minute,
			Steps: []Step{
				{Name: "suspicious powershell", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool {
					return (baseName(ev.Image) == "powershell.exe" || baseName(ev.Image) == "pwsh.exe") && hasAny(ev.CommandLine, psSuspicious...)
				}},
				internet("internet connection"),
				{Name: "started or wrote a program", Kinds: KindProc | KindFile, Match: func(ev *Event, _ *proc) bool {
					if ev.Kind == KindFile {
						return execFile(ev.Path) && userWritable(ev.Path)
					}
					b := baseName(ev.Image)
					return b != "conhost.exe" && b != "csc.exe" && b != "cvtres.exe"
				}},
			},
		},
		{
			ID: "ioa_lsass_access_from_shell", Title: "Program started from a shell or a user folder read LSASS memory",
			Severity: "critical", Tactic: "credential-access", Technique: "T1003.001", OS: "windows", Window: 30 * time.Minute,
			Steps: []Step{
				{Name: "started", Kinds: KindProc, Match: func(ev *Event, p *proc) bool {
					return in(winShells, parentImage(ev, p)) || in(winScriptHosts, parentImage(ev, p)) || userWritable(ev.Image) ||
						in(set("rundll32.exe"), ev.Image)
				}},
				{Name: "lsass read", Kinds: KindAccess, Match: func(ev *Event, _ *proc) bool {
					return lsass(ev.TargetImage) && ev.Access&procVMRead != 0
				}},
			},
		},
		{
			ID: "ioa_userdir_exe_injection", Title: "Program from a user folder injected into another process",
			Severity: "medium", Tactic: "defense-evasion", Technique: "T1055", OS: "windows", Window: 30 * time.Minute,
			Steps: []Step{
				{Name: "started from user folder", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool { return userWritable(ev.Image) }},
				{Name: "injection", Kinds: KindThread | KindAccess, Match: func(ev *Event, _ *proc) bool {
					if baseName(ev.TargetImage) == baseName(ev.Image) || ev.TargetImage == "" {
						return false
					}
					if ev.Kind == KindThread {
						return true
					}
					return ev.Access&(procVMWrite|procCreateThread) == procVMWrite|procCreateThread
				}},
			},
		},
		{
			ID: "ioa_download_then_exec", Title: "Downloader wrote a program that was then run",
			Severity: "high", Tactic: "command-and-control", Technique: "T1105", Window: 15 * time.Minute,
			Steps: []Step{
				{Name: "downloader", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool { return in(downloaders, ev.Image) }},
				{Name: "wrote", Kinds: KindFile, Capture: path, Match: func(ev *Event, _ *proc) bool {
					return userWritable(ev.Path) && execFile(ev.Path)
				}},
				{Name: "ran it", Kinds: KindProc, Keyed: true},
			},
		},
		{
			ID: "ioa_webserver_shell", Title: "Web server started a shell that ran recon or reached out",
			Severity: "high", Tactic: "persistence", Technique: "T1505.003", Window: 10 * time.Minute,
			Steps: []Step{
				{Name: "shell under web server", Kinds: KindProc, Match: func(ev *Event, p *proc) bool {
					return in(shells, ev.Image) && in(webServers, parentImage(ev, p))
				}},
				{Name: "recon, egress or dropped program", Kinds: KindProc | KindNet | KindFile, Match: func(ev *Event, _ *proc) bool {
					switch ev.Kind {
					case KindProc:
						return in(reconTools, ev.Image) || hasAny(ev.CommandLine, "/etc/passwd", "/etc/shadow")
					case KindNet:
						return ev.Public
					}
					return userWritable(ev.Path) && execFile(ev.Path)
				}},
			},
		},
		{
			ID: "ioa_reverse_shell", Title: "Reverse shell: a shell or interpreter with socket arguments connected out",
			Severity: "critical", Tactic: "execution", Technique: "T1059", Window: 2 * time.Minute,
			Steps: []Step{
				{Name: "shell with socket", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool {
					return in(reverseShellImages, ev.Image) && hasAny(ev.CommandLine, reverseShellKW...)
				}},
				{Name: "connected", Kinds: KindNet, Match: func(ev *Event, _ *proc) bool {
					return ev.DestIP != "" && !strings.HasPrefix(ev.DestIP, "127.") && ev.DestIP != "::1"
				}},
			},
		},
		{
			ID: "ioa_tmp_exec_injection", Title: "Program from a temp folder attached to or wrote into another process",
			Severity: "high", Tactic: "defense-evasion", Technique: "T1055", OS: "linux", Window: 30 * time.Minute,
			Steps: []Step{
				{Name: "started from temp", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool { return userWritable(ev.Image) }},
				{Name: "process access", Kinds: KindAccess, Match: func(ev *Event, _ *proc) bool {
					switch ev.Action {
					case "attach", "seize", "poketext", "pokedata", "setregs", "vm_write", "mem_write":
						return true
					}
					return false
				}},
			},
		},
		{
			ID: "ioa_tmp_exec_root", Title: "Program from a temp folder run by a user became root",
			Severity: "high", Tactic: "privilege-escalation", Technique: "T1068", OS: "linux", Window: 10 * time.Minute,
			Steps: []Step{
				{Name: "started from temp by a user", Kinds: KindProc, Match: func(ev *Event, _ *proc) bool {
					return userWritable(ev.Image) && ev.User != "" && ev.User != "0"
				}},
				{Name: "became root", Kinds: KindPriv, Match: func(ev *Event, _ *proc) bool {
					if !strings.HasPrefix(ev.Action, "setres") && !strings.HasPrefix(ev.Action, "setre") && ev.Action != "setuid" && ev.Action != "setgid" {
						return false
					}
					for _, id := range strings.Split(ev.IDs, ",") {
						if id == "0" {
							return true
						}
					}
					return false
				}},
			},
		},
	}
}

// ─── the detection line ──────────────────────────────────────────────

// Detection is one reported chain.
type Detection struct {
	Rule              *Rule
	Action            string // detected
	Image             string // the process of the last step
	PID               uint32
	CommandLine       string
	User              string
	AnchorImage       string // the process the chain started in
	AnchorPID         uint32
	AnchorCommandLine string
	ParentImage       string // the anchor's parent
	Chain             []string
}

// kv quotes a value for the server's kv parser: \" and \\ escaped, line
// breaks as spaces.
func kv(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(s)
	if len(s) > 2048 {
		s = s[:2048]
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// Line formats d as the ioa_detection decoder reads it.
func Line(d Detection) string {
	var sb strings.Builder
	r := d.Rule
	fmt.Fprintf(&sb, "event=ioa action=%s rule=%s severity=%s tactic=%s technique=%s title=%s",
		d.Action, r.ID, r.Severity, r.Tactic, r.Technique, kv(r.Title))
	fmt.Fprintf(&sb, " image=%s pid=%d command_line=%s user=%s", kv(d.Image), d.PID, kv(d.CommandLine), kv(d.User))
	fmt.Fprintf(&sb, " anchor_image=%s anchor_pid=%d anchor_command_line=%s parent_image=%s",
		kv(d.AnchorImage), d.AnchorPID, kv(d.AnchorCommandLine), kv(d.ParentImage))
	fmt.Fprintf(&sb, " chain=%s", kv(strings.Join(d.Chain, " > ")))
	return sb.String()
}
