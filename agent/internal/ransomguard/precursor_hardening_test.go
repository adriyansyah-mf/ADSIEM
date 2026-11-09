package ransomguard

import (
	"errors"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/linsensor"
)

var errFake = errors.New("exit status 1")

func treeWith(base map[uint32]proc, extra ...proc) map[uint32]proc {
	out := map[uint32]proc{}
	for k, v := range base {
		out[k] = v
	}
	for _, p := range extra {
		out[p.pid] = p
	}
	return out
}

func has1(lines []string, parts ...string) bool {
	if len(lines) != 1 {
		return false
	}
	for _, p := range parts {
		if !strings.Contains(lines[0], p) {
			return false
		}
	}
	return true
}

// I1: the parent PID a process claims can be spoofed; the creator (the ETW
// event header PID) cannot. Only processes the agent itself started are
// exempt, never "the parent is the agent".
func TestSpoofedParentIsWalkedFromTheCreator(t *testing.T) {
	// Spoofed to the agent: not exempt, the real creator's tree dies.
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(ProcessStart{PID: 3200, PPID: 9999, CreatorPID: 3100, Image: vssadminExe,
		CommandLine: `vssadmin delete shadows /all /quiet`, Time: t0})
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 3000 || !has1(l, "response=killed", "PID=3000 ", "ParentSpoofed=true") {
		t.Fatalf("spoofed to the agent: killed %v lines %q", r.killed, l)
	}
	// Spoofed to explorer (protected): the creator is walked, not explorer.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(ProcessStart{PID: 3200, PPID: 2000, CreatorPID: 3000, Image: bcdeditExe,
		CommandLine: `bcdedit /set {default} recoveryenabled no`, Time: t0})
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 3000 || !has1(l, "ParentSpoofed=true") || strings.Contains(l[0], "InitiatorProtected") {
		t.Fatalf("spoofed to explorer: killed %v lines %q", r.killed, l)
	}
	// Creator equal to the claimed parent: no ParentSpoofed field.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(ProcessStart{PID: 3200, PPID: 3100, CreatorPID: 3100, Image: vssadminExe,
		CommandLine: `vssadmin delete shadows /all /quiet`, Time: t0})
	if l := r.lines(); len(l) != 1 || strings.Contains(l[0], "ParentSpoofed") {
		t.Fatalf("lines %q", l)
	}
	// A header PID equal to the process itself is no creator.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(ProcessStart{PID: 3200, PPID: 3100, CreatorPID: 3200, Image: vssadminExe,
		CommandLine: `vssadmin delete shadows /all /quiet`, Time: t0})
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 3000 || strings.Contains(l[0], "ParentSpoofed") {
		t.Fatalf("self creator: killed %v lines %q", r.killed, l)
	}
}

func TestOnlyTheAgentsOwnChildrenAreExempt(t *testing.T) {
	tree := treeWith(winTree, proc{pid: 8800, ppid: 9999, image: cmdExe})
	// A live-response command the agent started (cmd 8800) running vssadmin.
	r := newPrecursorRig(t, "windows", tree)
	r.g.own = func(pid uint32) bool { return pid == 8800 }
	r.g.ObserveProcess(ProcessStart{PID: 8810, PPID: 8800, CreatorPID: 8800, Image: vssadminExe,
		CommandLine: `vssadmin delete shadows /for=Z: /quiet`, Time: t0})
	if l := r.lines(); len(l) != 0 || len(r.killed) != 0 {
		t.Fatalf("own child acted on: killed %v lines %q", r.killed, l)
	}
	// Claiming that child as parent does not borrow its exemption.
	r.g.ObserveProcess(ProcessStart{PID: 3200, PPID: 8800, CreatorPID: 3000, Image: vssadminExe,
		CommandLine: `vssadmin delete shadows /all /quiet`, Time: t0})
	if len(r.killed) != 1 || r.killed[0] != 3000 {
		t.Fatalf("spoofed to an own child: killed %v", r.killed)
	}
	// A process whose parent is the agent but that the agent did not record
	// is not exempt: the agent is protected, so only the precursor dies.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(ProcessStart{PID: 3200, PPID: 9999, CreatorPID: 9999, Image: vssadminExe,
		CommandLine: `vssadmin delete shadows /all /quiet`, Time: t0})
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 3200 || !has1(l, "InitiatorProtected=true") {
		t.Fatalf("parent is the agent: killed %v lines %q", r.killed, l)
	}
}

// I2: a kernel-driver precursor also removes the services the initiator
// created (the driver's and IronChain's persistence service) and a dropped
// driver.
func TestBYOVDRemovesServicesAndTheDroppedDriver(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3150, 3000, scExe,
		`sc create IronChainSvc binPath= C:\Users\bob\AppData\Local\Temp\_MEI1\IronChain.exe start= auto`))
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("a plain service is not a precursor: %q", l)
	}
	const drv = `C:\Users\bob\AppData\Local\Temp\_MEI1\ThrottleStop.sys`
	r.g.ObserveProcess(winStart(3160, 3000, scExe, `sc create ThrottleStop type= kernel binPath= `+drv))
	want := []string{"sc stop throttlestop", "sc delete throttlestop", "sc stop ironchainsvc", "sc delete ironchainsvc"}
	if len(r.cmds) != len(want) {
		t.Fatalf("cmds %q", r.cmds)
	}
	for i, w := range want {
		if strings.Join(r.cmds[i], " ") != w {
			t.Fatalf("cmd %d = %q, want %q", i, r.cmds[i], w)
		}
	}
	if len(r.removed) != 1 || !strings.EqualFold(strings.ReplaceAll(r.removed[0], "/", `\`), drv) {
		t.Fatalf("removed %q", r.removed)
	}
	if l := r.lines(); !has1(l, "Precursor=byovd", "response=killed", `Reverted="service:throttlestop,service:ironchainsvc"`, "Removed=") {
		t.Fatalf("lines %q", l)
	}

	// In System32\drivers and not written by the tree: the services go,
	// the file stays (it may be a legitimate driver).
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3160, 3100, scExe,
		`sc create BdApiUtil type= kernel binPath= C:\Windows\System32\drivers\BdApiUtil.sys`))
	if len(r.killed) != 1 || len(r.removed) != 0 || len(r.cmds) != 2 {
		t.Fatalf("killed %v removed %q cmds %q", r.killed, r.removed, r.cmds)
	}

	// report_only: nothing removed.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.SetRuntime(Runtime{Kill: false})
	r.g.ObserveProcess(winStart(3160, 3000, scExe, `sc create ThrottleStop type= kernel binPath= `+drv))
	if len(r.cmds) != 0 || len(r.removed) != 0 {
		t.Fatalf("report_only: cmds %q removed %q", r.cmds, r.removed)
	}
}

// A driver copied into System32\drivers by a child of the initiator
// (cmd /c copy, cmd.exe from System32, no rename source) is the tree's drop.
func TestBYOVDDropByAChildOfTheInitiator(t *testing.T) {
	const drv = `C:\Windows\System32\drivers\x.sys`
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(7050, 7000, cmdExe, `cmd /c copy C:\Users\bob\x.sys `+drv))
	r.g.Observe(linsensor.FileEvent{Time: t0, PID: 7050, Image: cmdExe, Action: "create", Path: drv})
	r.g.ObserveProcess(winStart(7100, 7000, scExe, `sc create x type= kernel binPath= System32\drivers\x.sys`))
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 7000 || !has1(l, "confirmed=true", "Precursor=byovd") {
		t.Fatalf("killed %v lines %q", r.killed, l)
	}
	if len(r.removed) != 1 {
		t.Fatalf("the tree's drop is removed: %q", r.removed)
	}
}

// I3: a renamed copy of a tool is that tool (PE OriginalFilename).
func TestRenamedToolIsIdentifiedByOriginalFilename(t *testing.T) {
	const renamed = `C:\Users\bob\AppData\Local\Temp\a.exe`
	r := newPrecursorRig(t, "windows", winTree)
	r.g.origName = func(image string) string {
		if image == renamed {
			return "VSSADMIN.EXE"
		}
		return ""
	}
	r.g.ObserveProcess(winStart(3200, 3100, renamed, `a.exe delete shadows /all /quiet`))
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 3000 || !has1(l, "Precursor=shadow_delete") {
		t.Fatalf("killed %v lines %q", r.killed, l)
	}
	// Without a version resource, the image name decides: a.exe is no tool.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3200, 3100, renamed, `a.exe delete shadows /all /quiet`))
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("lines %q", l)
	}
}

// I3: what AMSI saw a script do goes through the PowerShell rules, even when
// the launch command line is obfuscated.
func TestAMSIScriptContent(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	r.g.ObserveProcess(winStart(3300, 3100, psExe, `powershell -nop -w hidden -c "iex $env:x"`))
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("launch line: %q", l)
	}
	r.g.ObserveScript(3300, psExe, []byte("Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"))
	if l := r.lines(); len(r.killed) != 1 || r.killed[0] != 3000 || !has1(l, "Precursor=shadow_delete", "PrecursorPID=3300", "Source=amsi") {
		t.Fatalf("killed %v lines %q", r.killed, l)
	}
	// Benign script: nothing.
	r = newPrecursorRig(t, "windows", winTree)
	r.g.ObserveScript(3300, psExe, []byte("Get-CimInstance Win32_ShadowCopy | Select-Object ID"))
	if l := r.lines(); len(l) != 0 {
		t.Fatalf("lines %q", l)
	}
}

// I5: snapshot rotation by known tooling or a schedule from a root-owned
// system program is reported, not killed, unless the same initiator also
// did something else; a security product stopped by an installed program
// likewise. User-writable initiators are killed as before.
func TestSnapshotRotationIsReportOnly(t *testing.T) {
	tree := treeWith(linTree,
		proc{pid: 1610, ppid: 1500, image: "/usr/bin/sh"},
		proc{pid: 3000, ppid: 1, image: "/usr/bin/perl"},
		proc{pid: 3100, ppid: 900, image: "/tmp/x"},
	)
	// zfs-auto-snapshot from cron
	r := newPrecursorRig(t, "linux", tree)
	r.g.ObserveProcess(linStart(1610, 1500, "/usr/bin/sh", "/bin/sh /usr/sbin/zfs-auto-snapshot --quiet --syslog --label=hourly --keep=24 //"))
	r.g.ObserveProcess(linStart(1620, 1610, "/usr/sbin/zfs", "zfs destroy -d tank/data@zfs-auto-snap_hourly-2026-11-09-0900"))
	if l := r.lines(); len(r.killed) != 0 || !has1(l, "confirmed=true response=none", "Precursor=snapshot_delete", "downgraded=rotation_tool") {
		t.Fatalf("zfs-auto-snapshot: killed %v lines %q", r.killed, l)
	}
	// Proxmox vzdump (perl)
	r = newPrecursorRig(t, "linux", tree)
	r.g.ObserveProcess(linStart(3000, 1, "/usr/bin/perl", "/usr/bin/perl /usr/bin/vzdump 100 --mode snapshot"))
	r.g.ObserveProcess(linStart(3010, 3000, "/usr/sbin/lvremove", "lvremove -f /dev/pve/snap_vm-100-disk-0_vzdump"))
	if l := r.lines(); len(r.killed) != 0 || !has1(l, "downgraded=rotation_tool") {
		t.Fatalf("vzdump: killed %v lines %q", r.killed, l)
	}
	// ...unless that initiator also hit another category: then it is killed.
	r.g.ObserveProcess(linStart(3020, 3000, "/usr/sbin/insmod", "insmod /tmp/rk.ko"))
	r.g.ObserveProcess(linStart(3030, 3000, "/usr/sbin/lvremove", "lvremove -f /dev/pve/snap_vm-101-disk-0"))
	if len(r.killed) != 2 || r.killed[1] != 3000 {
		t.Fatalf("mixed categories: killed %v lines %q", r.killed, r.lines())
	}
	// A user-writable program naming a rotation tool gets no pass.
	r = newPrecursorRig(t, "linux", tree)
	r.g.ObserveProcess(linStart(3100, 900, "/tmp/x", "/tmp/x /usr/sbin/sanoid --cron"))
	r.g.ObserveProcess(linStart(3110, 3100, "/usr/sbin/zfs", "zfs destroy tank/data@autosnap_2026"))
	if len(r.killed) != 1 || r.killed[0] != 3100 {
		t.Fatalf("/tmp/x: killed %v", r.killed)
	}
}

func TestDefenseTamperFromInstalledProgramIsReportOnly(t *testing.T) {
	// An RMM or vendor updater in Program Files swapping an antivirus.
	r := newPrecursorRig(t, "windows", winTree)
	for i, c := range []string{`sc stop AVP`, `sc config AVP start= disabled`, `sc delete AVP`} {
		r.g.ObserveProcess(winStart(7100+uint32(i), 7000, scExe, c))
	}
	if l := r.lines(); len(r.killed) != 0 || !has1(l, "Precursor=defense_tamper", "response=none", "downgraded=trusted_initiator") {
		t.Fatalf("Program Files: killed %v lines %q", r.killed, l)
	}
	// Critical precursors from that program are still stopped.
	r.g.ObserveProcess(winStart(7200, 7000, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if len(r.killed) != 1 || r.killed[0] != 7000 {
		t.Fatalf("critical from Program Files: killed %v", r.killed)
	}
	// A spoofed parent never earns the downgrade.
	r = newPrecursorRig(t, "windows", winTree)
	for i, c := range []string{`sc stop AVP`, `sc config AVP start= disabled`, `sc delete AVP`} {
		r.g.ObserveProcess(ProcessStart{PID: 7100 + uint32(i), PPID: 7000, CreatorPID: 3000, Image: scExe, CommandLine: c, Time: t0})
	}
	if len(r.killed) != 1 || r.killed[0] != 3000 {
		t.Fatalf("spoofed: killed %v lines %q", r.killed, r.lines())
	}
}

// Responses run on a bounded pool, not a goroutine per event.
func TestPrecursorWorkerPool(t *testing.T) {
	r := newPrecursorRig(t, "windows", winTree)
	r.g.async = true
	r.g.ObserveProcess(winStart(3200, 3100, vssadminExe, `vssadmin delete shadows /all /quiet`))
	if l := r.out.wait(t, 1); !strings.Contains(l[0], "response=killed") {
		t.Fatalf("lines %q", l)
	}
	if cap(r.g.pre.jobs) != precursorQueue {
		t.Fatalf("queue %d", cap(r.g.pre.jobs))
	}
}
