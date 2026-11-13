//go:build windows

package task

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A quarantined program that is already running must be stopped; a copy of
// ping.exe elsewhere stands in for it, and the real ping.exe keeps running.
func TestStopRunningKillsProcessesOfTheFileOnly(t *testing.T) {
	src := filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE")
	dir := t.TempDir()
	evil := filepath.Join(dir, "invoice.exe")
	in, err := os.Open(src)
	if err != nil {
		t.Skip(err)
	}
	out, err := os.Create(evil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(out, in)
	in.Close()
	out.Close()

	run := func(path string) *exec.Cmd {
		cmd := exec.Command(path, "-n", "60", "127.0.0.1")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		return cmd
	}
	target, other := run(evil), run(src)
	time.Sleep(300 * time.Millisecond)

	stopped := StopRunning(evil)
	if len(stopped) != 1 || stopped[0] != target.Process.Pid {
		t.Fatalf("StopRunning = %v, want [%d]", stopped, target.Process.Pid)
	}
	done := make(chan struct{})
	go func() { _, _ = target.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the process running the file is still alive")
	}
	if got := processesRunning(src); len(got) == 0 {
		t.Fatal("the real ping.exe must keep running")
	}
	_ = other
}
