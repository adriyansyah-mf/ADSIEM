//go:build linux

package task

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestHelperSleep is the program the StopRunning test copies and runs: the
// test binary itself, sleeping. Copies of /bin/sleep do not work everywhere
// (a coreutils multicall binary picks its tool from its own file name, so a
// copy called ".7625e6d2e" exits at once).
func TestHelperSleep(t *testing.T) {
	if os.Getenv("STOPRUNNING_HELPER") != "1" {
		t.Skip("helper process for TestStopRunningKillsProcessesOfTheFileOnly")
	}
	time.Sleep(60 * time.Second)
}

func copyExe(t *testing.T, dst string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
}

func start(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, "-test.run=^TestHelperSleep$")
	cmd.Env = append(os.Environ(), "STOPRUNNING_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd
}

func gone(cmd *exec.Cmd) bool {
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

// waitRunning waits until path shows up as the executable of a process.
func waitRunning(t *testing.T, path string) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if pids := processesRunning(path); len(pids) > 0 || time.Now().After(deadline) {
			return pids
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A quarantined program that is already running must be stopped, including
// one that deleted its own file (it keeps running from memory).
func TestStopRunningKillsProcessesOfTheFileOnly(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, ".7625e6d2e")
	copyExe(t, evil)
	running := start(t, evil)

	deleted := filepath.Join(dir, "dropper")
	copyExe(t, deleted)
	gonefile := start(t, deleted)
	if pids := waitRunning(t, deleted); len(pids) != 1 {
		t.Fatalf("dropper not running: %v", pids)
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}

	other := filepath.Join(dir, "unrelated")
	copyExe(t, other)
	bystander := start(t, other)

	if got := waitRunning(t, evil); len(got) != 1 || got[0] != running.Process.Pid {
		t.Fatalf("processesRunning(%s) = %v, want [%d]", evil, got, running.Process.Pid)
	}
	stopped := StopRunning(evil)
	if len(stopped) != 1 || !gone(running) {
		t.Fatalf("the process running the file must be stopped: %v", stopped)
	}
	if stopped := StopRunning(deleted); len(stopped) != 1 || !gone(gonefile) {
		t.Fatalf("a process whose file was deleted must be stopped too: %v", stopped)
	}
	if err := bystander.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("an unrelated process must keep running")
	}
	if got := StopRunning(filepath.Join(dir, "nothing-runs-this")); len(got) != 0 {
		t.Fatalf("nothing to stop: %v", got)
	}
}
