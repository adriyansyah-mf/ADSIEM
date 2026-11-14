//go:build linux

package task

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	mode os.FileMode
	st   syscall.Stat_t
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 1 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &f.st }

// A dropped hard link of a root-owned binary shares its inode: locking it
// would lock the system binary. An attacker's own file is quarantined
// whatever its links.
func TestQuarantineRefusesRootOwnedHardLinks(t *testing.T) {
	cases := []struct {
		name  string
		info  fakeInfo
		allow bool
	}{
		{"root file, one link", fakeInfo{st: syscall.Stat_t{Nlink: 1, Uid: 0}}, true},
		{"root file, a second link", fakeInfo{st: syscall.Stat_t{Nlink: 2, Uid: 0}}, false},
		{"www-data file, linked", fakeInfo{st: syscall.Stat_t{Nlink: 3, Uid: 33}}, true},
		{"directory", fakeInfo{mode: os.ModeDir, st: syscall.Stat_t{Nlink: 1}}, false},
		{"symlink", fakeInfo{mode: os.ModeSymlink, st: syscall.Stat_t{Nlink: 1}}, false},
		{"fifo", fakeInfo{mode: os.ModeNamedPipe, st: syscall.Stat_t{Nlink: 1}}, false},
	}
	for _, c := range cases {
		err := checkQuarantineTarget("/tmp/x", c.info)
		if (err == nil) != c.allow {
			t.Errorf("%s: err=%v, want allowed=%v", c.name, err, c.allow)
		}
	}
}

// stat follows a symlink: without the preflight, quarantining /tmp/l ->
// /usr/bin/sshd stopped sshd and then failed with "is a symlink".
func TestQuarantineOfASymlinkStopsNothing(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "daemon")
	copyExe(t, real)
	running := start(t, real)
	if pids := waitRunning(t, real); len(pids) != 1 {
		t.Fatalf("not running: %v", pids)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	initQuarantineState(t.TempDir())
	if _, err := quarantineAndStop(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlink must be refused: %v", err)
	}
	if err := running.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("the symlink's target was stopped")
	}
}

// The host has /x/shared/payload; a process in another mount namespace runs
// its own, different /x/shared/payload. Quarantining the host file must not
// stop that process.
func TestSamePathInAnotherNamespaceIsNotTheFile(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	if err := exec.Command("unshare", "-Urm", "true").Run(); err != nil {
		t.Skipf("unprivileged mount namespaces unavailable: %v", err)
	}
	base := t.TempDir()
	privdir, shared := filepath.Join(base, "privdir"), filepath.Join(base, "shared")
	for _, d := range []string{privdir, shared} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hostFile := filepath.Join(shared, "payload")
	copyExe(t, hostFile)                          // the host's file
	copyExe(t, filepath.Join(privdir, "payload")) // the other namespace's file
	cmd := exec.Command("unshare", "-Urm", "sh", "-c",
		`mount --bind "$1" "$2" && exec "$3" -test.run='^TestHelperSleep$'`, "sh", privdir, shared, hostFile)
	cmd.Env = append(os.Environ(), "STOPRUNNING_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		link, _ := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
		if link == hostFile || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pids := processesRunning(hostFile); len(pids) != 0 {
		t.Fatalf("a different file under the same path matched: %v", pids)
	}
	initQuarantineState(t.TempDir())
	out, err := quarantineAndStop(hostFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.StoppedPIDs) != 0 || cmd.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatalf("the other namespace's program was stopped: %v", out.StoppedPIDs)
	}
	_ = os.Chmod(hostFile, 0o600)
}
