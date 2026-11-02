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
