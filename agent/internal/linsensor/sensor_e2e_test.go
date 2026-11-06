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
		// The agent reads the target's image from /proc when it handles
		// the record; killing the target at once raced that on busy hosts.
		time.Sleep(time.Second)
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
	case "memaccess":
		return memAccessHelper()
	}
	return 1
}

// memAccessHelper reads a sleeping child's memory with process_vm_readv,
// writes the same bytes back with process_vm_writev, opens its
// /proc/<pid>/mem and reads /etc/shadow: what a credential dumper does.
func memAccessHelper() int {
	target := exec.Command("sleep", "5")
	if err := target.Start(); err != nil {
		return 2
	}
	defer target.Process.Kill()
	time.Sleep(200 * time.Millisecond) // exec done: /proc shows sleep
	pid := target.Process.Pid
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var start uint64
	fmt.Sscanf(strings.SplitN(string(maps), "-", 2)[0], "%x", &start)
	buf := make([]byte, 16)
	local := []unix.Iovec{{Base: &buf[0], Len: uint64(len(buf))}}
	remote := []unix.RemoteIovec{{Base: uintptr(start), Len: len(buf)}}
	if _, err := unix.ProcessVMReadv(pid, local, remote, 0); err != nil {
		fmt.Fprintln(os.Stderr, "process_vm_readv:", err)
		return 2
	}
	if _, err := unix.ProcessVMWritev(pid, local, remote, 0); err != nil {
		// the first mapping may be read-only: the attempt failed, nothing to report
		fmt.Fprintln(os.Stderr, "process_vm_writev (not required):", err)
	}
	if f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid)); err == nil {
		f.Close()
	} else {
		fmt.Fprintln(os.Stderr, "open mem:", err)
		return 2
	}
	if f, err := os.Open("/etc/shadow"); err == nil {
		f.Close()
	} else {
		fmt.Fprintln(os.Stderr, "open shadow:", err)
		return 2
	}
	time.Sleep(time.Second) // the agent reads the target's image from /proc
	return 0
}

type collected struct {
	mu    sync.Mutex
	lines []string
	files []FileEvent
	diag  func() string // sensor counters, printed when a wait fails
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
	diag := ""
	if c.diag != nil {
		diag = c.diag() // takes c.mu itself
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("no line with %q (%s); got:\n%s", parts, diag, strings.Join(c.lines, "\n"))
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
	c.diag = func() string {
		c.mu.Lock()
		n := len(c.files)
		c.mu.Unlock()
		return fmt.Sprintf("drops=%d file_events=%d bpf=%v", s.drops(), n, s.stats())
	}
	defer func() { t.Log(c.diag()) }()

	// CI runners may symlink coreutils (/usr/bin/mv → /usr/bin/gnumv); the
	// sensor reports the kernel-resolved path, so file events match on Comm
	// and "sleep" is resolved the same way before matching TargetImage.
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	if resolved, rerr := filepath.EvalSymlinks(sleepPath); rerr == nil {
		sleepPath = resolved
	}

	dir := t.TempDir()
	sh := exec.Command("sh", "-c", "cd "+dir+" && echo x > rel.txt && mv rel.txt moved.txt && rm moved.txt && mkdir d && rmdir d")
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	rel := filepath.Join(dir, "rel.txt")
	moved := filepath.Join(dir, "moved.txt")
	c.wait(t, LogFile, "action=create", `TargetFilename="`+rel+`"`, `Comm="sh"`)
	c.wait(t, LogFile, "action=rename", `TargetFilename="`+moved+`"`, `SourceFilename="`+rel+`"`, `Comm="mv"`)
	c.wait(t, LogFile, "action=delete", `TargetFilename="`+moved+`"`, `Comm="rm"`)
	c.wait(t, LogFile, "action=delete", `TargetFilename="`+filepath.Join(dir, "d")+`"`, "IsDirectory=true")

	if err := runHelper(t, "fileless").Run(); err != nil {
		t.Fatalf("fileless helper: %v", err)
	}
	c.wait(t, LogMemfd, `MemfdName="e2e-payload"`)
	c.wait(t, LogFileless, `Image="/memfd:e2e-payload"`, `ExecPath="/proc/self/fd/`, "Links=0")

	if err := runHelper(t, "ptrace").Run(); err != nil {
		t.Fatalf("ptrace helper: %v", err)
	}
	c.wait(t, LogPtrace, "action=attach", `TargetImage="`+sleepPath+`"`)

	if err := runHelper(t, "setuid").Run(); err != nil {
		t.Fatalf("setuid helper: %v", err)
	}
	c.wait(t, LogPrivilege, "action=setuid", `IDs="0"`, "User=1000", "EUID=0")

	mem := runHelper(t, "memaccess")
	if err := mem.Run(); err != nil {
		t.Fatalf("memaccess helper: %v", err)
	}
	c.wait(t, LogProcessAccess, "action=vm_read", `TargetImage="`+sleepPath+`"`)
	c.wait(t, LogProcessAccess, "action=mem_read", `TargetImage="`+sleepPath+`"`)
	c.wait(t, LogFile, "action=read", `TargetFilename="/etc/shadow"`)

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
