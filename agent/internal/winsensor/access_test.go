package winsensor

import (
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

func openProc(src uint32, target, access, rc string) *etw.Event {
	return &etw.Event{Provider: auditAPIProvider, ID: auditOpenProcess, PID: src, Props: []etw.Property{
		{Name: "TargetProcessId", Value: target}, {Name: "DesiredAccess", Value: access}, {Name: "ReturnCode", Value: rc},
	}}
}

func threadEv(creator uint32, target string) *etw.Event {
	return &etw.Event{Provider: kernelProcessProvider, ID: threadStartEvent, PID: creator, Props: []etw.Property{
		{Name: "ProcessID", Value: target}, {Name: "TThreadId", Value: "9100"}, {Name: "Win32StartAddr", Value: "0x7ff6a1b20000"},
	}}
}

func accessSetup() (*processJoiner, *accessTracker) {
	j := joiner()
	j.remember(&process{pid: 700, image: `C:\Windows\System32\lsass.exe`, user: `NT AUTHORITY\SYSTEM`})
	j.remember(&process{pid: 6788, image: `C:\Users\alice\AppData\Local\Temp\dump.exe`, user: `WIN01\alice`})
	j.remember(&process{pid: 4100, image: `C:\Windows\explorer.exe`, user: `WIN01\alice`})
	j.remember(&process{pid: 600, image: `C:\Windows\System32\csrss.exe`, user: `NT AUTHORITY\SYSTEM`})
	return j, newAccessTracker(j, 999)
}

func TestLsassMemoryReadIsReported(t *testing.T) {
	_, a := accessSetup()
	now := time.Now()
	got := a.openProcess(openProc(6788, "700", "0x1010", "0"), now)
	want := `EventID=10 Channel="ETW" Provider="Microsoft-Windows-Kernel-Audit-API-Calls" SourceProcessId="6788" ` +
		`SourceImage="C:\Users\alice\AppData\Local\Temp\dump.exe" SourceUser="WIN01\alice" TargetProcessId="700" ` +
		`TargetImage="C:\Windows\System32\lsass.exe" GrantedAccess="0x1010"`
	if got != want {
		t.Fatalf("line\n got %s\nwant %s", got, want)
	}
	if again := a.openProcess(openProc(6788, "700", "0x1010", "0"), now.Add(time.Minute)); again != "" {
		t.Fatal("the same access is reported once per window")
	}
	if later := a.openProcess(openProc(6788, "700", "0x1010", "0"), now.Add(11*time.Minute)); later == "" {
		t.Fatal("reported again after the window")
	}
}

func TestOnlyInjectionRightsOrLsassAreReported(t *testing.T) {
	_, a := accessSetup()
	now := time.Now()
	cases := []struct {
		ev   *etw.Event
		want bool
	}{
		{openProc(6788, "4100", "0x1F0FFF", "0"), true},        // all access to explorer: can inject
		{openProc(6788, "4100", "0x0020", "0"), true},          // VM_WRITE
		{openProc(6788, "4100", "0x1000", "0"), false},         // query limited information
		{openProc(6788, "4100", "0x0010", "0"), false},         // reading a non-lsass process
		{openProc(6788, "700", "0x1000", "0"), false},          // lsass without VM_READ
		{openProc(6788, "700", "0x1010", "0xC0000022"), false}, // access denied: nothing opened
		{openProc(4, "700", "0x1010", "0"), false},             // System
		{openProc(999, "700", "0x1010", "0"), false},           // the agent itself
		{openProc(6788, "6788", "0x1FFFFF", "0"), false},       // itself
		{openProc(600, "4100", "0x1FFFFF", "0"), false},        // csrss opens every new process
	}
	for i, c := range cases {
		got := a.openProcess(c.ev, now)
		if (got != "") != c.want {
			t.Errorf("case %d: got %q", i, got)
		}
	}
}

func TestRemoteThreadButNotAProcessesFirstThread(t *testing.T) {
	j, a := accessSetup()
	now := time.Now()
	got := a.threadStart(threadEv(6788, "4100"), now)
	for _, want := range []string{`EventID=8 `, `SourceImage="C:\Users\alice\AppData\Local\Temp\dump.exe"`,
		`TargetImage="C:\Windows\explorer.exe"`, `StartAddress="0x7ff6a1b20000"`, `NewThreadId="9100"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	// explorer started notepad a moment ago: notepad's first thread comes from explorer
	j.remember(&process{pid: 5200, ppid: 4100, image: `C:\Windows\notepad.exe`, started: now.Add(-time.Second)})
	if got := a.threadStart(threadEv(4100, "5200"), now); got != "" {
		t.Fatalf("a new process's first thread is not injection: %s", got)
	}
	if got := a.threadStart(threadEv(4100, "4100"), now); got != "" {
		t.Fatal("a thread in its own process")
	}
}
