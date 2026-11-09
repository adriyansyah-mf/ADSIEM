// Package ownproc records the processes the agent itself starts (live
// response commands, its own bcdedit/sc reverts, PowerShell collectors), so
// the anti-ransomware precursor checks can tell the agent's own commands
// from a process that merely claims the agent as its parent (a spoofed
// parent PID). A process is recorded from its start until keepAfterExit
// after it exits: the events of the children it started arrive late.
package ownproc

import (
	"bytes"
	"os/exec"
	"sync"
	"time"
)

const (
	keepAfterExit = 2 * time.Minute
	maxEntries    = 4096
)

type entry struct {
	exited time.Time // zero while running
}

// Registry is a bounded set of PIDs.
type Registry struct {
	mu  sync.Mutex
	m   map[uint32]entry
	now func() time.Time
}

func New() *Registry { return &Registry{m: map[uint32]entry{}, now: time.Now} }

// Add records a started process.
func (r *Registry) Add(pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) >= maxEntries {
		r.expire()
		if len(r.m) >= maxEntries {
			r.m = map[uint32]entry{}
		}
	}
	r.m[pid] = entry{}
}

// Done marks pid exited; it is forgotten keepAfterExit later.
func (r *Registry) Done(pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[pid]; ok {
		r.m[pid] = entry{exited: r.now()}
	}
}

// Has reports whether pid is a process the agent started (still running or
// exited less than keepAfterExit ago).
func (r *Registry) Has(pid uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[pid]
	if !ok {
		return false
	}
	if !e.exited.IsZero() && r.now().Sub(e.exited) >= keepAfterExit {
		delete(r.m, pid)
		return false
	}
	return true
}

func (r *Registry) expire() {
	now := r.now()
	for pid, e := range r.m {
		if !e.exited.IsZero() && now.Sub(e.exited) >= keepAfterExit {
			delete(r.m, pid)
		}
	}
}

func (r *Registry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// Default is the agent's registry.
var Default = New()

// Has reports whether the agent started pid (Default).
func Has(pid uint32) bool { return Default.Has(pid) }

// Run starts cmd, records it, and waits for it.
func Run(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := uint32(cmd.Process.Pid)
	Default.Add(pid)
	defer Default.Done(pid)
	return cmd.Wait()
}

// Output is exec.Cmd.Output through Run.
func Output(cmd *exec.Cmd) ([]byte, error) {
	var out bytes.Buffer
	cmd.Stdout = &out
	err := Run(cmd)
	return out.Bytes(), err
}

// CombinedOutput is exec.Cmd.CombinedOutput through Run.
func CombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := Run(cmd)
	return out.Bytes(), err
}
