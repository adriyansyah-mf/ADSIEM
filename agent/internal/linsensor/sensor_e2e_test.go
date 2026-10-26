//go:build linux

package linsensor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The end-to-end test loads the real eBPF object, so it needs root, BTF
// and tracefs. Run it with LINSENSOR_E2E=1 (CI does, under sudo; locally:
// a privileged container, see docs/operations/linux-sensor.md). The work
// it observes happens in child processes: the sensor ignores the agent's
// own process, which here is the test binary.

func TestMain(m *testing.M) {
	if h := os.Getenv("LINSENSOR_HELPER"); h != "" {
		os.Exit(helper(h))
	}
	os.Exit(m.Run())
}

func helper(what string) int {
	switch what {
	case "fileless":
		fd, err := unix.MemfdCreate("e2e-payload", 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		img, err := os.ReadFile("/bin/true")
		if err != nil {
			return 2
		}
		unix.Write(fd, img)
		err = syscall.Exec(fmt.Sprintf("/proc/self/fd/%d", fd), []string{"e2e-payload"}, os.Environ())
		fmt.Fprintln(os.Stderr, "exec:", err)
		return 2
	case "ptrace":
		runtime.LockOSThread()
		target := exec.Command("sleep", "5")
		if err := target.Start(); err != nil {
			return 2
		}
		defer target.Process.Kill()
		if err := unix.PtraceAttach(target.Process.Pid); err != nil {
			fmt.Fprintln(os.Stderr, "attach:", err)
			return 2
		}
		var ws unix.WaitStatus
		unix.Wait4(target.Process.Pid, &ws, 0, nil)
		unix.PtraceDetach(target.Process.Pid)
		return 0
	case "setuid":
		// Real uid 1000, effective 0 (like a setuid-root binary run by a
		// user), then become root for real.
		runtime.LockOSThread()
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, 1000, 0, 0); e != 0 {
			fmt.Fprintln(os.Stderr, "setresuid:", e)
			return 2
		}
		if _, _, e := unix.RawSyscall(unix.SYS_SETUID, 0, 0, 0); e != 0 {
			fmt.Fprintln(os.Stderr, "setuid:", e)
			return 2
		}
		return 0
	case "exit7":
		return 7
	}
	return 1
}

type collected struct {
	mu    sync.Mutex
	lines []string
	files []FileEvent
}

func (c *collected) push(logType, line string) {
	c.mu.Lock()
	c.lines = append(c.lines, logType+" "+line)
	c.mu.Unlock()
}

func (c *collected) file(f FileEvent) {
	c.mu.Lock()
	c.files = append(c.files, f)
	c.mu.Unlock()
}

// wait returns the first line containing every part, or fails.
func (c *collected) wait(t *testing.T, parts ...string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, l := range c.lines {
			ok := true
			for _, p := range parts {
				ok = ok && strings.Contains(l, p)
			}
			if ok {
				c.mu.Unlock()
				return l
			}
		}
		c.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("no line with %q; got:\n%s", parts, strings.Join(c.lines, "\n"))
	return ""
}

func runHelper(t *testing.T, what string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "LINSENSOR_HELPER="+what)
	cmd.Stderr = os.Stderr
	return cmd
}

// TestSensorVolume reports how many lines the sensor ships on this host:
// LINSENSOR_VOLUME=60s go test -run TestSensorVolume (as root).
func TestSensorVolume(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("LINSENSOR_VOLUME"))
	if err != nil {
		t.Skip("set LINSENSOR_VOLUME to a duration")
	}
	var c collected
	var raw int
	var mu sync.Mutex
	s, err := Start(Options{Push: c.push, OnFile: func(FileEvent) { mu.Lock(); raw++; mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(d)
	drops := s.drops()
	s.Stop()
	counts := map[string]int{}
	for _, l := range c.lines {
		counts[strings.SplitN(l, " ", 2)[0]]++
	}
	perMin := func(n int) float64 { return float64(n) / d.Minutes() }
	for lt, n := range counts {
		t.Logf("%-24s %6d lines  %8.1f/min", lt, n, perMin(n))
	}
	t.Logf("%-24s %6d events %8.1f/min (before rate limiting)", "file events seen", raw, perMin(raw))
	t.Logf("ring buffer drops: %d", drops)
}

func TestSensorEndToEnd(t *testing.T) {
	if os.Getenv("LINSENSOR_E2E") != "1" {
		t.Skip("set LINSENSOR_E2E=1 (needs root, BTF and tracefs)")
	}
	var c collected
	s, err := Start(Options{Push: c.push, OnFile: c.file})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	dir := t.TempDir()
	sh := exec.Command("sh", "-c", "cd "+dir+" && echo x > rel.txt && mv rel.txt moved.txt && rm moved.txt && mkdir d && rmdir d")
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	rel := filepath.Join(dir, "rel.txt")
	moved := filepath.Join(dir, "moved.txt")
	c.wait(t, LogFile, "action=create", `TargetFilename="`+rel+`"`, `Comm="sh"`)
	c.wait(t, LogFile, "action=rename", `TargetFilename="`+moved+`"`, `SourceFilename="`+rel+`"`, `Image="/usr/bin/mv"`)
	c.wait(t, LogFile, "action=delete", `TargetFilename="`+moved+`"`, `Image="/usr/bin/rm"`)
	c.wait(t, LogFile, "action=delete", `TargetFilename="`+filepath.Join(dir, "d")+`"`, "IsDirectory=true")

	if err := runHelper(t, "fileless").Run(); err != nil {
		t.Fatalf("fileless helper: %v", err)
	}
	c.wait(t, LogMemfd, `MemfdName="e2e-payload"`)
	c.wait(t, LogFileless, `Image="/memfd:e2e-payload"`, `ExecPath="/proc/self/fd/`, "Links=0")

	if err := runHelper(t, "ptrace").Run(); err != nil {
		t.Fatalf("ptrace helper: %v", err)
	}
	c.wait(t, LogPtrace, "action=attach", `TargetImage="/usr/bin/sleep"`)

	if err := runHelper(t, "setuid").Run(); err != nil {
		t.Fatalf("setuid helper: %v", err)
	}
	c.wait(t, LogPrivilege, "action=setuid", `IDs="0"`, "User=1000", "EUID=0")

	cmd := runHelper(t, "exit7")
	cmd.Run()
	c.wait(t, LogExit, "ExitCode=7", fmt.Sprintf("PID=%d", cmd.Process.Pid))

	// The test process itself (the "agent") is never reported.
	os.WriteFile(filepath.Join(dir, "self.txt"), []byte("x"), 0o644)
	time.Sleep(500 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		if strings.Contains(l, "self.txt") {
			t.Fatalf("the sensor reported its own process: %s", l)
		}
	}
	if len(c.files) == 0 {
		t.Fatal("OnFile saw no file events")
	}
}
