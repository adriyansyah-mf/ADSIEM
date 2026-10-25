package winsensor

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

// Properties as the Windows runner reported them (session_windows_test.go).
func kernelStart(pid, ppid, cmd string) *etw.Event {
	return &etw.Event{Provider: "{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}", Opcode: opcodeStart, Props: []etw.Property{
		{Name: "ProcessId", Value: pid}, {Name: "ParentId", Value: ppid},
		{Name: "UserSID", Value: `\\WIN01\alice`}, {Name: "ImageFileName", Value: "cmd.exe"},
		{Name: "CommandLine", Value: cmd},
	}}
}

func providerStart(pid, ppid, image string) *etw.Event {
	return &etw.Event{Provider: kernelProcessProvider, ID: 1, Props: []etw.Property{
		{Name: "ProcessID", Value: pid}, {Name: "ParentProcessID", Value: ppid},
		{Name: "MandatoryLabel", Value: "S-1-16-12288"}, {Name: "ImageName", Value: image},
	}}
}

func joiner() *processJoiner {
	return newProcessJoiner(func(uint32) string { return "" }, func(p string) string {
		return strings.Replace(p, `\Device\HarddiskVolume3`, `C:`, 1)
	})
}

func TestProcessStartJoinsBothHalves(t *testing.T) {
	j := joiner()
	now := time.Now()
	j.kernel(&etw.Event{Opcode: opcodeDCStart, Props: []etw.Property{
		{Name: "ProcessId", Value: "0x3F4"}, {Name: "ImageFileName", Value: `C:\Windows\explorer.exe`},
		{Name: "CommandLine", Value: `C:\Windows\Explorer.EXE`},
	}}, now)
	if got := j.kernel(kernelStart("0x920", "0x3F4", `cmd.exe /c "echo hi"`), now); got != nil {
		t.Fatalf("emitted before the provider half: %v", got)
	}
	got := j.provider(providerStart("2336", "1012", `\Device\HarddiskVolume3\Windows\System32\cmd.exe`), now)
	if len(got) != 1 {
		t.Fatalf("lines %v", got)
	}
	want := `EventID=1 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="2336" ` +
		`Image="C:\Windows\System32\cmd.exe" CommandLine="cmd.exe /c \"echo hi\"" User="WIN01\alice" ` +
		`IntegrityLevel="High" ParentProcessId="1012" ParentImage="C:\Windows\explorer.exe" ParentCommandLine="C:\Windows\Explorer.EXE"`
	if got[0] != want {
		t.Fatalf("line\n got %s\nwant %s", got[0], want)
	}
}

func TestProcessStartEmitsAHalfAfterTheJoinWindow(t *testing.T) {
	j := joiner()
	now := time.Now()
	j.kernel(kernelStart("0x10", "0x4", "whoami.exe /all"), now)
	if got := j.flush(now.Add(joinWindow / 2)); got != nil {
		t.Fatalf("flushed too early: %v", got)
	}
	got := j.flush(now.Add(joinWindow))
	if len(got) != 1 || !strings.Contains(got[0], `CommandLine="whoami.exe /all"`) || !strings.Contains(got[0], `Image="cmd.exe"`) {
		t.Fatalf("lines %v", got)
	}
	if len(j.pending) != 0 {
		t.Fatal("a flushed start is still pending")
	}
}

func TestProcessImageFallsBackToTheRunningProcess(t *testing.T) {
	j := newProcessJoiner(func(pid uint32) string {
		if pid == 16 {
			return `C:\Tools\whoami.exe`
		}
		return ""
	}, func(p string) string { return p })
	now := time.Now()
	j.kernel(kernelStart("0x10", "0x4", "whoami.exe"), now)
	got := j.flush(now.Add(joinWindow))
	if len(got) != 1 || !strings.Contains(got[0], `Image="C:\Tools\whoami.exe"`) {
		t.Fatalf("lines %v", got)
	}
}

func TestProcessJoinerIsBounded(t *testing.T) {
	j := joiner()
	now := time.Now()
	for i := 0; i < maxPending+50; i++ {
		j.kernel(kernelStart(fmt.Sprintf("0x%X", i+1), "0x4", "x"), now.Add(time.Duration(i)))
	}
	if len(j.pending) > maxPending {
		t.Fatalf("%d pending", len(j.pending))
	}
	for i := 0; i < maxKnown+100; i++ {
		j.remember(&process{pid: uint32(100000 + i)})
	}
	if len(j.known) > maxKnown || len(j.order) > maxKnown {
		t.Fatalf("known %d order %d", len(j.known), len(j.order))
	}
}

func TestIntegrityLevels(t *testing.T) {
	for sid, want := range map[string]string{"S-1-16-4096": "Low", "S-1-16-8192": "Medium", "S-1-16-12288": "High",
		"S-1-16-16384": "System", "S-1-5-18": ""} {
		if got := integrityLevel(sid); got != want {
			t.Errorf("%s: %q, want %q", sid, got, want)
		}
	}
}
