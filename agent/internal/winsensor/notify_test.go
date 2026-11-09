package winsensor

import (
	"testing"
	"time"
)

// Execution prevention gets a start as soon as its full image path is known,
// once, not when both halves are joined.

func TestOnStartFiresOnTheKernelHalfWithTheLiveImage(t *testing.T) {
	j := joiner()
	j.fullImage = func(pid uint32) string {
		if pid == 0x920 {
			return `C:\Tools\evil.exe`
		}
		return ""
	}
	var got []ProcessStart
	j.onStart = func(p ProcessStart) { got = append(got, p) }
	now := time.Now()
	j.kernel(kernelStart("0x920", "0x3F4", "evil.exe -x"), now)
	if len(got) != 1 || got[0].Image != `C:\Tools\evil.exe` || got[0].PID != 0x920 || got[0].CommandLine != "evil.exe -x" {
		t.Fatalf("on the kernel half: %+v", got)
	}
	// the provider half completes the line, but prevention already had it
	if lines := j.provider(providerStart("2336", "1012", `\Device\HarddiskVolume3\Tools\evil.exe`), now); len(lines) != 1 {
		t.Fatalf("lines %v", lines)
	}
	if len(got) != 1 {
		t.Fatalf("onStart called %d times", len(got))
	}
}

func TestOnStartFiresOnTheProviderHalfFirst(t *testing.T) {
	j := joiner()
	var got []ProcessStart
	j.onStart = func(p ProcessStart) { got = append(got, p) }
	now := time.Now()
	j.provider(providerStart("2336", "1012", `\Device\HarddiskVolume3\Windows\System32\cmd.exe`), now)
	if len(got) != 1 || got[0].Image != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("on the provider half: %+v", got)
	}
	j.kernel(kernelStart("0x920", "0x3F4", "cmd.exe"), now)
	if len(got) != 1 {
		t.Fatalf("onStart called %d times", len(got))
	}
}

// A process gone before its path could be read: prevention gets it when the
// start is emitted, with what is known, as before.
func TestOnStartFallsBackToTheEmit(t *testing.T) {
	j := joiner() // fullImage finds nothing
	var got []ProcessStart
	j.onStart = func(p ProcessStart) { got = append(got, p) }
	now := time.Now()
	j.kernel(kernelStart("0x10", "0x4", "short.exe"), now)
	if len(got) != 0 {
		t.Fatalf("fired without a full path: %+v", got)
	}
	j.flush(now.Add(joinWindow))
	if len(got) != 1 || got[0].Image != "cmd.exe" {
		t.Fatalf("after the join window: %+v", got)
	}
}

// The anti-ransomware precursor checks need the command line, which only
// the kernel logger half has: onCommand fires on that half, once, even
// when the provider half came first (and onStart went without it).
func TestOnCommandFiresOnTheKernelHalfAfterTheProvider(t *testing.T) {
	j := joiner()
	var starts, cmds []ProcessStart
	j.onStart = func(p ProcessStart) { starts = append(starts, p) }
	j.onCommand = func(p ProcessStart) { cmds = append(cmds, p) }
	now := time.Now()
	j.provider(providerStart("2336", "1012", `\Device\HarddiskVolume3\Windows\System32\vssadmin.exe`), now)
	if len(starts) != 1 || starts[0].CommandLine != "" || len(cmds) != 0 {
		t.Fatalf("provider half: starts %+v cmds %+v", starts, cmds)
	}
	j.kernel(kernelStart("0x920", "0x3F4", "vssadmin delete shadows /all /quiet"), now)
	if len(cmds) != 1 || cmds[0].CommandLine != "vssadmin delete shadows /all /quiet" ||
		cmds[0].Image != `C:\Windows\System32\vssadmin.exe` || cmds[0].PID != 0x920 || cmds[0].PPID != 0x3F4 {
		t.Fatalf("kernel half: %+v", cmds)
	}
	j.flush(now.Add(joinWindow))
	if len(cmds) != 1 || len(starts) != 1 {
		t.Fatalf("fired again: starts %d cmds %d", len(starts), len(cmds))
	}
}

// The creator: the Kernel-Process start event is logged by the process
// that creates the new one, so its header PID is the real creator; the
// ParentProcessID field can be spoofed (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
// onCommand waits for both halves (or the join window) to carry it.
func TestOnCommandCarriesTheCreatorPID(t *testing.T) {
	j := joiner()
	var cmds []ProcessStart
	j.onCommand = func(p ProcessStart) { cmds = append(cmds, p) }
	now := time.Now()
	j.kernel(kernelStart("0x920", "0x3F4", "vssadmin delete shadows /all /quiet"), now)
	if len(cmds) != 0 {
		t.Fatalf("fired before the creator was known: %+v", cmds)
	}
	prov := providerStart("2336", "1012", `\Device\HarddiskVolume3\Windows\System32\vssadmin.exe`)
	prov.PID = 4242 // the real creator; ParentProcessID says 1012 (0x3F4)
	j.provider(prov, now)
	if len(cmds) != 1 || cmds[0].CreatorPID != 4242 || cmds[0].PPID != 0x3F4 || cmds[0].CommandLine == "" {
		t.Fatalf("cmds %+v", cmds)
	}

	// The provider half never comes: after the join window, without a creator.
	j = joiner()
	cmds = nil
	j.onCommand = func(p ProcessStart) { cmds = append(cmds, p) }
	j.kernel(kernelStart("0x930", "0x3F4", "bcdedit /set {default} recoveryenabled no"), now)
	j.flush(now.Add(joinWindow))
	if len(cmds) != 1 || cmds[0].CreatorPID != 0 || cmds[0].PID != 0x930 {
		t.Fatalf("after the window: %+v", cmds)
	}
}

func TestOnCommandFiresOnTheKernelHalfFirst(t *testing.T) {
	j := joiner()
	j.fullImage = func(uint32) string { return `C:\Windows\System32\bcdedit.exe` }
	var cmds []ProcessStart
	j.onCommand = func(p ProcessStart) { cmds = append(cmds, p) }
	now := time.Now()
	j.kernel(kernelStart("0x920", "0x3F4", "bcdedit /set {default} recoveryenabled no"), now)
	j.provider(providerStart("2336", "1012", `\Device\HarddiskVolume3\Windows\System32\bcdedit.exe`), now)
	if len(cmds) != 1 || cmds[0].Image != `C:\Windows\System32\bcdedit.exe` || cmds[0].CommandLine == "" {
		t.Fatalf("cmds %+v", cmds)
	}
}
