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

func copyExe(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Skipf("%s: %v", src, err)
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
	cmd := exec.Command(path, "60")
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

// A quarantined program that is already running must be stopped, including
// one that deleted its own file (it keeps running from memory).
func TestStopRunningKillsProcessesOfTheFileOnly(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, ".7625e6d2e")
	copyExe(t, "/bin/sleep", evil)
	running := start(t, evil)

	deleted := filepath.Join(dir, "dropper")
	copyExe(t, "/bin/sleep", deleted)
	gonefile := start(t, deleted)
	time.Sleep(200 * time.Millisecond) // let exec complete before the file goes
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}

	other := start(t, "/bin/sleep")

	if got := processesRunning(evil); len(got) != 1 || got[0] != running.Process.Pid {
		t.Fatalf("processesRunning(%s) = %v, want [%d]", evil, got, running.Process.Pid)
	}
	stopped := StopRunning(evil)
	if len(stopped) != 1 || !gone(running) {
		t.Fatalf("the process running the file must be stopped: %v", stopped)
	}
	if stopped := StopRunning(deleted); len(stopped) != 1 || !gone(gonefile) {
		t.Fatalf("a process whose file was deleted must be stopped too: %v", stopped)
	}
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("an unrelated process must keep running")
	}
	if got := StopRunning(filepath.Join(dir, "nothing-runs-this")); len(got) != 0 {
		t.Fatalf("nothing to stop: %v", got)
	}
}
