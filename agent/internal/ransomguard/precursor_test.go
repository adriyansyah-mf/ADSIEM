package ransomguard

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/siem-platform/agent/internal/linsensor"
)

// The IronChain process tree (Windows field case, 2026-11-08): the sample
// on the Desktop runs everything through cmd.exe.
var winTree = map[uint32]proc{
	4:    {pid: 4, ppid: 0, image: "System"},
	500:  {pid: 500, ppid: 400, image: `C:\Windows\System32\wininit.exe`},
	600:  {pid: 600, ppid: 500, image: `C:\Windows\System32\services.exe`},
	2000: {pid: 2000, ppid: 1900, image: `C:\Windows\explorer.exe`},
	3000: {pid: 3000, ppid: 2000, image: `C:\Users\bob\Desktop\9f2c1e.exe`},
	3100: {pid: 3100, ppid: 3000, image: `C:\Windows\System32\cmd.exe`},
	// an admin's console: explorer -> cmd
	4100: {pid: 4100, ppid: 2000, image: `C:\Windows\System32\cmd.exe`},
	// a malicious service: services.exe -> cmd
	5100: {pid: 5100, ppid: 600, image: `C:\Windows\System32\cmd.exe`},
	// look-alikes outside the system directory are not protected
	6000: {pid: 6000, ppid: 2000, image: `C:\Users\bob\AppData\Local\Temp\services.exe`},
	6100: {pid: 6100, ppid: 3000, image: `C:\Users\bob\AppData\Local\Temp\cmd.exe`},
	// an installed tool, not user-writable
	7000: {pid: 7000, ppid: 2000, image: `C:\Program Files\Tool\tool.exe`},
}

var linTree = map[uint32]proc{
	1:    {pid: 1, ppid: 0, image: "/usr/lib/systemd/systemd"},
	800:  {pid: 800, ppid: 1, image: "/usr/sbin/sshd"},
	900:  {pid: 900, ppid: 800, image: "/usr/bin/bash"},
	1000: {pid: 1000, ppid: 900, image: "/tmp/.x/locker"},
	1100: {pid: 1100, ppid: 1000, image: "/usr/bin/sh"},
	// cron -> sh: a nightly script
	1500: {pid: 1500, ppid: 1, image: "/usr/sbin/cron"},
	1600: {pid: 1600, ppid: 1500, image: "/usr/bin/sh"},
}

type precursorRig struct {
	g        *Guard
	out      *sink
	mu       sync.Mutex
	killed   []uint32
	cmds     [][]string
	isolated int
}

func newPrecursorRig(t *testing.T, goos string, tree map[uint32]proc) *precursorRig {
	t.Helper()
	r := &precursorRig{out: &sink{}}
	g := New(Options{Push: r.out.push, CanaryDirs: []string{t.TempDir() + "/none"}, Kill: true})
	g.goos = goos
	g.self = 9999
	g.async = false
	g.revertDelay = 0
	g.live = func() procLookup {
		return func(pid uint32) (proc, bool) { p, ok := tree[pid]; return p, ok }
	}
	g.cwd = func(uint32) string { return "" }
	g.response = func(pid uint32) (int, error) {
		r.mu.Lock()
		r.killed = append(r.killed, pid)
		r.mu.Unlock()
		return 3, nil
	}
	g.runCmd = func(name string, args ...string) error {
		r.mu.Lock()
		r.cmds = append(r.cmds, append([]string{name}, args...))
		r.mu.Unlock()
		return nil
	}
	r.g = g
	return r
}

func (r *precursorRig) lines() []string {
	r.out.mu.Lock()
	defer r.out.mu.Unlock()
	return append([]string(nil), r.out.lines...)
}

func winStart(pid, ppid uint32, image, cmd string) ProcessStart {
	return ProcessStart{PID: pid, PPID: ppid, Image: image, CommandLine: cmd, Time: t0}
}

const (
	vssadminExe = `C:\Windows\System32\vssadmin.exe`
	wbadminExe  = `C:\Windows\System32\wbadmin.exe`
	bcdeditExe  = `C:\Windows\System32\bcdedit.exe`
	scExe       = `C:\Windows\System32\sc.exe`
	netExe      = `C:\Windows\System32\net.exe`
	net1Exe     = `C:\Windows\System32\net1.exe`
	cmdExe      = `C:\Windows\System32\cmd.exe`
	wmicExe     = `C:\Windows\System32\wbem\WMIC.exe`
	psExe       = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
)

func encodedPS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Every critical Windows precursor, IronChain's command lines verbatim
// where it ran them: one is enough, the initiator (the Desktop sample, not
// cmd.exe) and its tree are killed.
func TestWindowsCriticalPrecursorsKillTheInitiator(t *testing.T) {
	cases := []struct {
		image, cmd, category string
	}{
		{vssadminExe, `vssadmin delete shadows /all /quiet`, "shadow_delete"},
		{cmdExe, `C:\Windows\system32\cmd.exe /c vssadmin delete shadows /all /quiet`, "shadow_delete"},
		{cmdExe, `cmd /c "vssadmin delete shadows /all /quiet & wmic shadowcopy delete"`, "shadow_delete"},
		{vssadminExe, `vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB`, "shadow_delete"},
		{wmicExe, `wmic shadowcopy delete`, "shadow_delete"},
		{wmicExe, `wmic.exe SHADOWCOPY /nointeractive DELETE`, "shadow_delete"},
		{psExe, `powershell -c "Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}"`, "shadow_delete"},
		{psExe, `powershell.exe -NoP -enc ` + encodedPS(`Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`), "shadow_delete"},
		{cmdExe, `cmd /c v^ssadmin del^ete shadows /all /quiet`, "shadow_delete"},
		{wbadminExe, `wbadmin delete catalog -quiet`, "backup_delete"},
		{wbadminExe, `wbadmin delete systemstatebackup -keepVersions:0`, "backup_delete"},
		{wbadminExe, `wbadmin DELETE BACKUP`, "backup_delete"},
		{bcdeditExe, `bcdedit /set {default} recoveryenabled no`, "boot_tamper"},
		{bcdeditExe, `bcdedit /set {default} bootstatuspolicy ignoreallfailures`, "boot_tamper"},
		{bcdeditExe, `bcdedit /set {default} safeboot minimal`, "boot_tamper"},
		{bcdeditExe, `bcdedit /set {default} safemode minimal`, "boot_tamper"},
		{scExe, `sc create BdApiUtil type= kernel binPath= C:\Windows\System32\drivers\BdApiUtil.sys`, "byovd"},
		{scExe, `sc create ThrottleStop type= kernel binPath= "C:\Users\bob\AppData\Local\Temp\_MEI53122\ThrottleStop.sys"`, "byovd"},
		{scExe, `sc.exe create kx type=kernel binpath=\??\C:\ProgramData\kx.sys`, "byovd"},
	}
	for _, c := range cases {
		t.Run(c.cmd, func(t *testing.T) {
			r := newPrecursorRig(t, "windows", winTree)
			r.g.ObserveProcess(winStart(3200, 3100, c.image, c.cmd))
			lines := r.lines()
			if len(lines) != 1 {
				t.Fatalf("lines = %q", lines)
			}
			want := "detection=precursor confirmed=true response=killed Precursor=" + c.category +
				" CommandLine=" + kv(c.cmd) + " PrecursorImage=" + kv(c.image) + " PrecursorPID=3200" +
				` Image="C:\\Users\\bob\\Desktop\\9f2c1e.exe" Comm="9f2c1e.exe" PID=3000 PPID=2000 User=0 Killed=3 Isolated=false`
			if !strings.HasPrefix(lines[0], want) {
				t.Fatalf("got  %s\nwant %s", lines[0], want)
			}
			if len(r.killed) != 1 || r.killed[0] != 3000 {
				t.Fatalf("killed %v, want the sample (3000)", r.killed)
			}
		})
	}
}

// Admins' everyday commands stay quiet, whoever runs them.
func TestWindowsEverydayAdminCommandsAreQuiet(t *testing.T) {
	quiet := []struct{ image, cmd string }{
		{vssadminExe, `vssadmin list shadows`},
		{vssadminExe, `vssadmin list shadowstorage`},
		{vssadminExe, `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%`},
		{vssadminExe, `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=20GB`},
		{vssadminExe, `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=UNBOUNDED`},
		{vssadminExe, `vssadmin delete shadows /for=C: /oldest`},
		{vssadminExe, `vssadmin create shadow /for=C:`},
		{wmicExe, `wmic shadowcopy list brief`},
		{wmicExe, `wmic shadowcopy call create Volume=C:\`},
		{psExe, `powershell -c "Get-WmiObject Win32_ShadowCopy | Select-Object ID,InstallDate"`},
		{wbadminExe, `wbadmin get versions`},
		{wbadminExe, `wbadmin start backup -backupTarget:E: -include:C: -quiet`},
		{wbadminExe, `wbadmin delete systemstatebackup -keepVersions:3`},
		{wbadminExe, `wbadmin delete backup -deleteOldest`},
		{bcdeditExe, `bcdedit /enum`},
		{bcdeditExe, `bcdedit /enum {current} /v`},
		{bcdeditExe, `bcdedit /set {default} recoveryenabled yes`},
		{bcdeditExe, `bcdedit /set {current} bootstatuspolicy displayallfailures`},
		{bcdeditExe, `bcdedit /deletevalue {default} safeboot`},
		{bcdeditExe, `bcdedit /timeout 5`},
		{scExe, `sc query WinDefend`},
		{scExe, `sc qc windefend`},
		{scExe, `sc start WinDefend`},
		{scExe, `sc create MySvc binPath= "C:\Program Files\My\svc.exe" start= auto`},
		{scExe, `sc create npcap type= kernel binPath= C:\Windows\System32\drivers\npcap.sys`},
		{netExe, `net start`},
		{netExe, `net start w32time`},
		{netExe, `net stop spooler`},
		{scExe, `sc stop spooler`},
		{psExe, `powershell Set-MpPreference -DisableRealtimeMonitoring $false`},
		{psExe, `powershell Get-MpPreference`},
		{cmdExe, `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f`},
		{cmdExe, `taskkill /f /im notepad.exe`},
		{cmdExe, `netsh advfirewall set allprofiles state on`},
		{cmdExe, `notepad C:\docs\backup-plan.txt`},
	}
	for _, q := range quiet {
		// From an admin's console (explorer -> cmd) and from a program in
		// Program Files: neither is a reason to act.
		for _, parent := range []uint32{4100, 7000} {
			r := newPrecursorRig(t, "windows", winTree)
			r.g.response = func(uint32) (int, error) { t.Errorf("%q killed", q.cmd); return 0, nil }
			for i := 0; i < 3; i++ { // repeated: still no score
				r.g.ObserveProcess(winStart(8000+uint32(i), parent, q.image, q.cmd))
			}
			if l := r.lines(); len(l) != 0 {
				t.Errorf("%q from %d reported: %q", q.cmd, parent, l)
			}
		}
	}
}

// IronChain's security-product kills: one command is not enough, three
// distinct ones from the same initiator within a minute are. net stop runs
// as cmd -> net -> net1: the same command three times over counts once.
func TestWindowsScorePrecursorsNeedThree(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3200, 3100, cmdExe, `cmd /c net stop AVP /y`))
	r.g.ObserveProcess(winStart(3201, 3200, netExe, `net  stop AVP /y`))
	r.g.ObserveProcess(winStart(3202, 3201, net1Exe, `C:\Windows\system32\net1  stop AVP /y`))
	r.g.ObserveProcess(winStart(3203, 3100, scExe, `sc config AVP start= disabled`))
	if l := r.lines(); len(l) != 0 || len(r.killed) != 0 {
		t.Fatalf("two indicators acted: %q %v", l, r.killed)
	}
	r.g.ObserveProcess(winStart(3204, 3100, scExe, `sc delete AVP`))
	lines := r.lines()
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "detection=precursor confirmed=true response=killed Precursor=defense_tamper") ||
		!strings.Contains(lines[0], "PID=3000 ") {
		t.Fatalf("lines = %q", lines)
	}
	if len(r.killed) != 1 || r.killed[0] != 3000 {
		t.Fatalf("killed %v", r.killed)
	}

	// Defender tampering counts too.
	r = newPrecursorRig(t, "windows", winTree)
	for i, c := range []string{
		`powershell -c "Add-MpPreference -ExclusionPath C:\Users\bob\AppData\Local\Temp"`,
		`powershell Set-MpPreference -DisableRealtimeMonitoring $true`,
		`netsh advfirewall set allprofiles state off`,
	} {
		r.g.ObserveProcess(winStart(3300+uint32(i), 3100, psExe, c))
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "Precursor=defense_tamper") {
		t.Fatalf("lines = %q", l)
	}

	// Others: taskkill, reg add, the agent's own service, a third-party AV.
	r = newPrecursorRig(t, "windows", winTree)
	for i, c := range []string{
		`taskkill /F /IM MsMpEng.exe`,
		`reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`,
		`net stop SIEMAgent`,
	} {
		r.g.ObserveProcess(winStart(3400+uint32(i), 3100, cmdExe, c))
	}
	if l := r.lines(); len(l) != 1 {
		t.Fatalf("lines = %q", l)
	}
}

func TestScoreWindowIsSixtySeconds(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	for i, c := range []string{`net stop WinDefend`, `sc config WinDefend start= disabled`, `sc delete WinDefend`} {
		p := winStart(3200+uint32(i), 3100, scExe, c)
		p.Time = t0.Add(time.Duration(i) * 40 * time.Second)
		r.g.ObserveProcess(p)
	}
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("indicators 80 s apart acted: %q", l)
	}
}

// Look-alikes: a services.exe or cmd.exe outside the system directory is
// neither protected nor walked past.
func TestLookAlikesAreNotTrusted(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(6200, 6000, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if len(r.killed) != 1 || r.killed[0] != 6000 {
		t.Fatalf("killed %v, want the fake services.exe (6000)", r.killed)
	}
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(6200, 6100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if len(r.killed) != 1 || r.killed[0] != 6100 {
		t.Fatalf("killed %v, want the fake cmd.exe (6100)", r.killed)
	}
}

// A precursor that comes straight from a protected process (a malicious
// service under services.exe, an admin's explorer console): only the
// precursor process dies.
func TestProtectedInitiatorKillsOnlyThePrecursor(t *testing.T) {
	for _, parent := range []uint32{5100, 4100} {
		r := newPrecursorRig(t, "windows", winTree)
		r.g.ObserveProcess(winStart(5200, parent, vssadminExe, `vssadmin delete shadows /all /quiet`))
		if len(r.killed) != 1 || r.killed[0] != 5200 {
			t.Fatalf("parent %d: killed %v, want only the precursor (5200)", parent, r.killed)
		}
		l := r.lines()
		if len(l) != 1 || !strings.Contains(l[0], "response=killed") || !strings.Contains(l[0], "InitiatorProtected=true") {
			t.Fatalf("lines = %q", l)
		}
	}
}

func TestPrecursorReportOnlyIsolateDedupe(t *testing.T) {
	// report_only: no kill, no revert.
	r := newPrecursorRig(t, "windows", winTree)
	r.g.SetRuntime(Runtime{Kill: false})
	r.g.ObserveProcess(winStart(3200, 3100, bcdeditExe, `bcdedit /set {default} safeboot minimal`))
	if l := r.lines(); len(l) != 1 || !strings.HasPrefix(l[0], "detection=precursor confirmed=true response=none") {
		t.Fatalf("lines = %q", l)
	}
	if len(r.killed) != 0 || len(r.cmds) != 0 {
		t.Fatalf("report_only acted: killed %v cmds %v", r.killed, r.cmds)
	}

	// isolate when set.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.opts.Isolate = func() error { r.isolated++; return nil }
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if r.isolated != 1 || !strings.Contains(r.lines()[0], "Isolated=true") {
		t.Fatalf("isolated %d, lines %q", r.isolated, r.lines())
	}

	// Every kill is reported, also within the 10-minute window: never a
	// silent kill (the alert rule's own suppression keeps it one alert).
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	p := winStart(3201, 3100, wbadminExe, `wbadmin delete catalog -quiet`)
	p.Time = t0.Add(5 * time.Minute)
	r.g.ObserveProcess(p)
	if l := r.lines(); len(l) != 2 || len(r.killed) != 2 ||
		!strings.Contains(l[1], "response=killed Precursor=backup_delete") || !strings.Contains(l[1], "PrecursorPID=3201") {
		t.Fatalf("lines %q killed %v", l, r.killed)
	}

	// Lines where nothing was done (report_only) are one per initiator in
	// 10 minutes.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.SetRuntime(Runtime{Kill: false})
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	r.g.ObserveProcess(p) // +5 min
	if l := r.lines(); len(l) != 1 {
		t.Fatalf("report_only repeats: %q", l)
	}
	p.Time = t0.Add(11 * time.Minute)
	r.g.ObserveProcess(p)
	if l := r.lines(); len(l) != 2 {
		t.Fatalf("after 10 min: lines %q", l)
	}

	// Policy off, the agent's own commands: nothing.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.SetRuntime(Runtime{Off: true})
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	r.g.SetRuntime(Runtime{Kill: true})
	r.g.ObserveProcess(winStart(3200, 9999, bcdeditExe, `bcdedit /set {default} safeboot minimal`))
	if l := r.lines(); len(l) != 0 || len(r.killed) != 0 {
		t.Fatalf("lines %q killed %v", l, r.killed)
	}
}

// Group-policy exclusions (scope ransomware) apply to precursors: matched
// on the initiator (image, command line) and on the precursor (image,
// command line). Excluded: no kill, no revert, response=excluded, once per
// initiator in 10 minutes.
func TestPrecursorPolicyExclusions(t *testing.T) {
	type check func(image, cmd string) bool
	cases := []struct {
		name string
		ex   check
	}{
		{"initiator image", func(image, _ string) bool { return strings.EqualFold(image, `C:\Users\bob\Desktop\9f2c1e.exe`) }},
		{"precursor image", func(image, _ string) bool { return strings.EqualFold(image, bcdeditExe) }},
		{"exact command line", func(_, cmd string) bool {
			return strings.Contains(strings.ToLower(cmd), "bcdedit /set {current} safeboot minimal")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPrecursorRig(t, "windows", winTree)
			r.g.SetRuntime(Runtime{Kill: true, ExcludedProcess: c.ex})
			for i := 0; i < 2; i++ {
				r.g.ObserveProcess(winStart(3200+uint32(i), 3100, bcdeditExe, `bcdedit /set {current} safeboot minimal`))
			}
			if len(r.killed) != 0 || len(r.cmds) != 0 {
				t.Fatalf("excluded: killed %v cmds %v", r.killed, r.cmds)
			}
			l := r.lines()
			if len(l) != 1 || !strings.HasPrefix(l[0], "detection=precursor confirmed=true response=excluded Precursor=boot_tamper") {
				t.Fatalf("lines %q", l)
			}
			// another command line from the same program is not excluded by
			// a command-line exclusion
			r.g.ObserveProcess(winStart(3300, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
			if c.name == "exact command line" && len(r.killed) != 1 {
				t.Fatalf("other command not stopped: killed %v", r.killed)
			}
		})
	}

	// A command-line exclusion for one Linux cron script: the script's own
	// command line (the initiator shell's) is matched too.
	tree := map[uint32]proc{}
	for k, v := range linTree {
		tree[k] = v
	}
	r := newPrecursorRig(t, "linux", tree)
	r.g.ObserveProcess(linStart(1600, 1500, "/usr/bin/sh", "/bin/sh /usr/local/sbin/rotate-snapshots.sh"))
	r.g.SetRuntime(Runtime{Kill: true, ExcludedProcess: func(_, cmd string) bool {
		return strings.Contains(cmd, "/usr/local/sbin/rotate-snapshots.sh")
	}})
	r.g.ObserveProcess(linStart(1700, 1600, "/usr/sbin/lvremove", "lvremove -f vg0/home_snap"))
	if l := r.lines(); len(r.killed) != 0 || len(l) != 1 || !strings.Contains(l[0], "response=excluded") {
		t.Fatalf("cron script excluded: killed %v lines %q", r.killed, l)
	}

	// The image-only callback (older policy plumbing) still excludes.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.SetRuntime(Runtime{Kill: true, Excluded: func(image string) bool { return strings.HasSuffix(image, `9f2c1e.exe`) }})
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if l := r.lines(); len(r.killed) != 0 || len(l) != 1 || !strings.Contains(l[0], "response=excluded") {
		t.Fatalf("image exclusion: killed %v lines %q", r.killed, l)
	}
}

// After a boot-configuration precursor the change is undone.
func TestBootTamperIsReverted(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3200, 3100, cmdExe,
		`cmd /c bcdedit /set {default} recoveryenabled no & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {current} safeboot minimal`))
	want := [][]string{
		{"bcdedit", "/set", "{default}", "recoveryenabled", "yes"},
		{"bcdedit", "/set", "{default}", "bootstatuspolicy", "displayallfailures"},
		{"bcdedit", "/deletevalue", "{current}", "safeboot"},
	}
	if len(r.cmds) != len(want) {
		t.Fatalf("cmds = %q", r.cmds)
	}
	for i := range want {
		if strings.Join(r.cmds[i], " ") != strings.Join(want[i], " ") {
			t.Fatalf("cmd %d = %q, want %q", i, r.cmds[i], want[i])
		}
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], `Reverted="recoveryenabled,bootstatuspolicy,safeboot"`) {
		t.Fatalf("lines = %q", l)
	}
}

// BYOVD with the driver in System32\drivers: a hit when the same tree (or a
// process from a user-writable directory) wrote it there, not otherwise.
func TestBYOVDDriverDroppedIntoDrivers(t *testing.T) {
	const drv = `C:\Windows\System32\drivers\BdApiUtil.sys`
	cmd := `sc create BdApiUtil type= kernel binPath= ` + drv

	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(7100, 7000, scExe, cmd))
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("installed tool, driver not dropped: %q", l)
	}

	r = newPrecursorRig(t, "windows", winTree)
	r.g.Observe(linsensor.FileEvent{Time: t0, PID: 7000, Image: `C:\Program Files\Tool\tool.exe`, Action: "create", Path: drv})
	r.g.ObserveProcess(winStart(7100, 7000, scExe, cmd))
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "Precursor=byovd") {
		t.Fatalf("driver dropped by the initiator: %q", l)
	}

	r = newPrecursorRig(t, "windows", winTree)
	r.g.Observe(linsensor.FileEvent{Time: t0, PID: 50, Image: `C:\Windows\System32\cmd.exe`, Action: "rename",
		From: `C:\Users\bob\AppData\Local\Temp\_MEI53122\BdApiUtil.sys`, Path: drv})
	r.g.ObserveProcess(winStart(7100, 7000, scExe, cmd))
	if l := r.lines(); len(l) != 1 {
		t.Fatalf("driver moved from Temp: %q", l)
	}
}

func linStart(pid, ppid uint32, image, cmd string) ProcessStart {
	return ProcessStart{PID: pid, PPID: ppid, Image: image, CommandLine: cmd, Time: t0}
}

func TestLinuxCriticalPrecursors(t *testing.T) {
	cases := []struct{ image, cmd, category string }{
		{"/usr/sbin/lvremove", "lvremove -f vg0/home_snap", "snapshot_delete"},
		{"/usr/sbin/zfs", "zfs destroy -r tank/data@daily-2026-11-01", "snapshot_delete"},
		{"/usr/bin/btrfs", "btrfs subvolume delete /.snapshots/12/snapshot", "snapshot_delete"},
		{"/usr/bin/btrfs", "btrfs sub del /mnt/@snapshots/home-1", "snapshot_delete"},
		{"/usr/bin/sh", "sh -c lvremove -y /dev/vg0/root-snap", "snapshot_delete"},
		{"/usr/sbin/insmod", "insmod /tmp/.x/rk.ko", "kernel_module"},
		{"/usr/sbin/modprobe", "modprobe /dev/shm/x.ko.xz", "kernel_module"},
		{"/usr/sbin/insmod", "insmod /home/bob/../../var/tmp/m.ko", "kernel_module"},
	}
	for _, c := range cases {
		t.Run(c.cmd, func(t *testing.T) {
			r := newPrecursorRig(t, "linux", linTree)
			r.g.ObserveProcess(linStart(1200, 1100, c.image, c.cmd))
			l := r.lines()
			want := "detection=precursor confirmed=true response=killed Precursor=" + c.category +
				" CommandLine=" + kv(c.cmd) + " PrecursorImage=" + kv(c.image) + ` PrecursorPID=1200 Image="/tmp/.x/locker" Comm="locker" PID=1000 PPID=900`
			if len(l) != 1 || !strings.HasPrefix(l[0], want) {
				t.Fatalf("lines %q\nwant %s", l, want)
			}
			if len(r.killed) != 1 || r.killed[0] != 1000 {
				t.Fatalf("killed %v", r.killed)
			}
		})
	}
	// A relative module path resolves against the process's directory.
	r := newPrecursorRig(t, "linux", linTree)
	r.g.cwd = func(pid uint32) string {
		if pid == 1200 {
			return "/dev/shm"
		}
		return ""
	}
	r.g.ObserveProcess(linStart(1200, 1100, "/usr/sbin/insmod", "insmod ./rk.ko"))
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "Precursor=kernel_module") {
		t.Fatalf("relative module: %q", l)
	}
}

func TestLinuxEverydayAdminCommandsAreQuiet(t *testing.T) {
	for _, q := range []struct{ image, cmd string }{
		{"/usr/sbin/lvs", "lvs"},
		{"/usr/sbin/lvremove", "lvremove vg0/old_lv"},
		{"/usr/sbin/lvcreate", "lvcreate -s -n home_snap -L 1G vg0/home"},
		{"/usr/sbin/zfs", "zfs list -t snapshot"},
		{"/usr/sbin/zfs", "zfs snapshot tank/data@daily"},
		{"/usr/sbin/zfs", "zfs destroy tank/scratch"},
		{"/usr/bin/btrfs", "btrfs subvolume list /"},
		{"/usr/bin/btrfs", "btrfs subvolume snapshot / /.snapshots/13/snapshot"},
		{"/usr/sbin/modprobe", "modprobe nf_conntrack"},
		{"/usr/sbin/insmod", "insmod /lib/modules/6.1.0/extra/vboxdrv.ko"},
		{"/usr/bin/systemctl", "systemctl stop nginx"},
		{"/usr/bin/systemctl", "systemctl status auditd"},
		{"/usr/bin/systemctl", "systemctl restart siem-agent"},
	} {
		r := newPrecursorRig(t, "linux", linTree)
		r.g.response = func(uint32) (int, error) { t.Errorf("%q killed", q.cmd); return 0, nil }
		for i := 0; i < 3; i++ {
			r.g.ObserveProcess(linStart(1200+uint32(i), 1100, q.image, q.cmd))
		}
		if l := r.lines(); len(l) != 0 {
			t.Errorf("%q reported: %q", q.cmd, l)
		}
	}
}

func TestLinuxScoreAndProtected(t *testing.T) {
	r := newPrecursorRig(t, "linux", linTree)
	r.g.ObserveProcess(linStart(1200, 1100, "/usr/bin/systemctl", "systemctl stop siem-agent"))
	r.g.ObserveProcess(linStart(1201, 1100, "/usr/bin/systemctl", "systemctl disable siem-agent.service"))
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("two indicators: %q", l)
	}
	r.g.ObserveProcess(linStart(1202, 1100, "/usr/bin/systemctl", "systemctl mask auditd"))
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], "Precursor=defense_tamper") || r.killed[0] != 1000 {
		t.Fatalf("lines %q killed %v", l, r.killed)
	}

	// A nightly cron script removing an LVM snapshot: cron is protected,
	// only lvremove dies (the documented false-positive cost).
	r = newPrecursorRig(t, "linux", linTree)
	r.g.ObserveProcess(linStart(1700, 1600, "/usr/sbin/lvremove", "lvremove -f vg0/home_snap"))
	if len(r.killed) != 1 || r.killed[0] != 1700 || !strings.Contains(r.lines()[0], "InitiatorProtected=true") {
		t.Fatalf("killed %v lines %q", r.killed, r.lines())
	}
	// An admin over ssh: sshd is protected.
	r = newPrecursorRig(t, "linux", linTree)
	r.g.ObserveProcess(linStart(1300, 900, "/usr/sbin/insmod", "insmod /home/bob/rk.ko"))
	if len(r.killed) != 1 || r.killed[0] != 1300 {
		t.Fatalf("killed %v", r.killed)
	}
}

// The walk ends at a process that is gone: the topmost shell is killed
// (cmd's parent exited), never a reused PID.
func TestInitiatorGoneAndPIDReuse(t *testing.T) {
	tree := map[uint32]proc{
		3100: {pid: 3100, ppid: 3000, image: `C:\Windows\System32\cmd.exe`},
	}
	r := newPrecursorRig(t, "windows", tree)
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if len(r.killed) != 1 || r.killed[0] != 3100 {
		t.Fatalf("killed %v, want the orphaned shell", r.killed)
	}

	// The sample's start was seen, then it exited and its PID went to
	// another program: the sample is reported, the new owner never killed.
	tree = map[uint32]proc{
		3000: {pid: 3000, ppid: 2000, image: `C:\Program Files\Other\other.exe`},
		3100: {pid: 3100, ppid: 3000, image: `C:\Windows\System32\cmd.exe`},
		2000: {pid: 2000, ppid: 1900, image: `C:\Windows\explorer.exe`},
	}
	r = newPrecursorRig(t, "windows", tree)
	r.g.ObserveProcess(winStart(3000, 2000, `C:\Users\bob\Desktop\9f2c1e.exe`, `9f2c1e.exe`))
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	for _, k := range r.killed {
		if k == 3000 {
			t.Fatal("killed a reused PID")
		}
	}
	if l := r.lines(); len(l) != 1 || !strings.Contains(l[0], `Image="C:\\Users\\bob\\Desktop\\9f2c1e.exe"`) {
		t.Fatalf("lines %q", l)
	}
}

// Safe Mode: the agent service is registered under SafeBoot\Minimal and
// \Network, once.
type fakeBootStore struct{ m map[string]string }

func (f *fakeBootStore) get(key string) (string, bool, error) { v, ok := f.m[key]; return v, ok, nil }
func (f *fakeBootStore) set(key, value string) error          { f.m[key] = value; return nil }

func TestSafeModeRegistration(t *testing.T) {
	s := &fakeBootStore{m: map[string]string{
		`SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SIEMAgent`: "Driver",
	}}
	changed, err := ensureSafeMode(s, "SIEMAgent")
	if err != nil || len(changed) != 2 {
		t.Fatalf("changed %v err %v", changed, err)
	}
	for _, k := range []string{`SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\SIEMAgent`,
		`SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SIEMAgent`} {
		if s.m[k] != "Service" {
			t.Fatalf("%s = %q", k, s.m[k])
		}
	}
	if changed, err := ensureSafeMode(s, "SIEMAgent"); err != nil || len(changed) != 0 {
		t.Fatalf("second run changed %v err %v", changed, err)
	}
}
