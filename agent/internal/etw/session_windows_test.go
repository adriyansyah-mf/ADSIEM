//go:build windows

package etw

import (
	"fmt"
	"os/exec"
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

func dump(t *testing.T, label string, e *Event) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s: provider=%s %q id=%d opcode=%d version=%d pid=%d truncated=%v\n",
		label, e.Provider, e.ProviderName, e.ID, e.Opcode, e.Version, e.PID, e.Truncated)
	for _, p := range e.Props {
		fmt.Fprintf(&b, "    %s = %s\n", p.Name, p.Value)
	}
	t.Log(b.String())
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
		fromKernel = kernelProc.find(func(e *Event) bool { v, _ := e.Get("ProcessId"); return e.Opcode == 1 && v == fmt.Sprint(pid) })
		fromProvider = user.find(func(e *Event) bool { v, _ := e.Get("ProcessID"); return e.ID == 1 && v == fmt.Sprint(pid) })
	}
	t.Logf("kernel session: %d events, %d decode errors; provider session: %d events, %d decode errors",
		len(kernelProc.events), ks.DecodeErrors(), len(user.events), us.DecodeErrors())
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
