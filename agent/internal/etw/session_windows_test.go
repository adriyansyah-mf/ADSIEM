//go:build windows

package etw

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Real sessions on a real Windows host (elevated, as the agent's service).

const kernelProcessProvider = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}" // Microsoft-Windows-Kernel-Process

type recorder struct {
	mu     sync.Mutex
	events []*Event
}

func (r *recorder) add(e *Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) find(match func(*Event) bool) *Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if match(e) {
			return e
		}
	}
	return nil
}

// dump logs one line per property: the Windows job only shows lines that
// carry the test file prefix.
func dump(t *testing.T, label string, e *Event) {
	t.Helper()
	t.Logf("%s: provider=%s %q id=%d opcode=%d version=%d pid=%d truncated=%v",
		label, e.Provider, e.ProviderName, e.ID, e.Opcode, e.Version, e.PID, e.Truncated)
	for _, p := range e.Props {
		t.Logf("%s:   %s = %s", label, p.Name, p.Value)
	}
}

// numeric reports whether property name of e holds n (TDH formats MOF ids
// in hex, manifest ones in decimal).
func numeric(e *Event, name string, n uint32) bool {
	v, ok := e.Get(name)
	if !ok {
		return false
	}
	got, err := strconv.ParseUint(v, 0, 32)
	return err == nil && uint32(got) == n
}

// TestProcessStartSources starts both candidate sources, runs a process with
// a marker on its command line and prints every property each source gave
// for it: which one carries the command line is decided from this, not
// assumed. It requires at least one source to report the process.
func TestProcessStartSources(t *testing.T) {
	kernelProc, user := &recorder{}, &recorder{}
	ks, err := Start(Config{Name: "SIEMAgent-Test-Kernel", KernelFlags: KernelProcess}, kernelProc.add)
	if err != nil {
		t.Fatalf("kernel session: %v", err)
	}
	defer ks.Close()
	us, err := Start(Config{Name: "SIEMAgent-Test-Process", Providers: []Provider{{GUID: kernelProcessProvider, Keywords: 0x10}}}, user.add)
	if err != nil {
		t.Fatalf("provider session: %v", err)
	}
	defer us.Close()
	time.Sleep(2 * time.Second) // sessions running

	marker := fmt.Sprintf("siem-etw-marker-%d", time.Now().UnixNano())
	cmd := exec.Command("cmd.exe", "/c", "echo", marker)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.ProcessState.Pid())

	deadline := time.Now().Add(15 * time.Second)
	var fromKernel, fromProvider *Event
	for time.Now().Before(deadline) && (fromKernel == nil || fromProvider == nil) {
		time.Sleep(500 * time.Millisecond)
		fromKernel = kernelProc.find(func(e *Event) bool { return e.Opcode == 1 && numeric(e, "ProcessId", pid) })
		fromProvider = user.find(func(e *Event) bool { return e.ID == 1 && numeric(e, "ProcessID", pid) })
	}
	t.Logf("kernel session: %d events, %d decode errors; provider session: %d events, %d decode errors",
		len(kernelProc.events), ks.DecodeErrors(), len(user.events), us.DecodeErrors())
	kernelProc.mu.Lock()
	opcodes := map[uint8]int{}
	for _, e := range kernelProc.events {
		opcodes[e.Opcode]++
	}
	var sample *Event
	if len(kernelProc.events) > 0 {
		sample = kernelProc.events[len(kernelProc.events)-1]
	}
	kernelProc.mu.Unlock()
	t.Logf("kernel session events by opcode: %v", opcodes)
	if fromKernel == nil && sample != nil {
		dump(t, "kernel logger sample (no start matched)", sample)
	}
	if fromKernel != nil {
		dump(t, "kernel logger process start", fromKernel)
	}
	if fromProvider != nil {
		dump(t, "Microsoft-Windows-Kernel-Process start", fromProvider)
	}
	if fromKernel == nil && fromProvider == nil {
		for i, e := range append(kernelProc.events[:min(3, len(kernelProc.events))], user.events[:min(3, len(user.events))]...) {
			dump(t, fmt.Sprintf("sample %d", i), e)
		}
		t.Fatalf("no source reported process %d", pid)
	}
	for label, e := range map[string]*Event{"kernel": fromKernel, "provider": fromProvider} {
		if e == nil {
			continue
		}
		for _, p := range e.Props {
			if strings.Contains(p.Value, marker) {
				t.Logf("%s source carries the command line in %q", label, p.Name)
			}
		}
	}
}

func TestStartReplacesAStaleSession(t *testing.T) {
	first, err := Start(Config{Name: "SIEMAgent-Test-Stale", Providers: []Provider{{GUID: kernelProcessProvider, Keywords: 0x10}}}, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	first.unregister() // as if its process died: the session itself keeps running
	second, err := Start(Config{Name: "SIEMAgent-Test-Stale", Providers: []Provider{{GUID: kernelProcessProvider, Keywords: 0x10}}}, func(*Event) {})
	if err != nil {
		t.Fatalf("a stale session was not replaced: %v", err)
	}
	second.Close()
}
