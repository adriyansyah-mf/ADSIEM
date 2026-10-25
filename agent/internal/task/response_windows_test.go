//go:build windows

package task

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These run on a real Windows host (CI: windows-latest, elevated).

// sleeper starts exe as a long-running child that pings for a minute.
func sleeper(t *testing.T, exe string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(exe, "/c", "ping", "-n", "60", "127.0.0.1")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd
}

func cmdExe(t *testing.T) string {
	t.Helper()
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(sys, "cmd.exe")
}

func TestKillProcessTerminatesAProcess(t *testing.T) {
	cmd := sleeper(t, cmdExe(t))
	res, err := killProcess(cmd.Process.Pid, false, 5)
	if err != nil {
		t.Fatalf("kill: %v (%+v)", err, res)
	}
	if !res.Exited || res.Comm != "cmd.exe" || res.Signal != "TerminateProcess" {
		t.Fatalf("result %+v", res)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the process is still running")
	}
}

func pidOf(t *testing.T, image string) int {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), image) {
			return int(e.ProcessID)
		}
	}
	t.Fatalf("%s not running", image)
	return 0
}

func TestKillProcessRefusesCriticalProcessesAndItself(t *testing.T) {
	for name, pid := range map[string]int{
		"lsass":    pidOf(t, "lsass.exe"),
		"services": pidOf(t, "services.exe"),
		"System":   4,
		"itself":   os.Getpid(),
	} {
		res, err := killProcess(pid, true, 1)
		if err == nil || res.Refused == "" {
			t.Fatalf("%s (pid %d) was not refused: %+v %v", name, pid, res, err)
		}
	}
}

// A critical name outside the system directory is not the real process.
func TestKillProcessAllowsACriticalNameOutsideSystem32(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "lsass.exe")
	b, err := os.ReadFile(cmdExe(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fake, b, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := sleeper(t, fake)
	res, err := killProcess(cmd.Process.Pid, false, 5)
	if err != nil || !res.Exited || res.Comm != "lsass.exe" {
		t.Fatalf("masquerading process not killed: %+v %v", res, err)
	}
}

func TestQuarantineLocksTheFileAndRestoreUnlocksIt(t *testing.T) {
	setQuarantineStore(filepath.Join(t.TempDir(), "quarantine.json"))
	t.Cleanup(func() { setQuarantineStore("") })
	path := filepath.Join(t.TempDir(), "payload.exe")
	if err := os.WriteFile(path, []byte("malware sample"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := quarantineFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = restoreFile(path) }) // let TempDir be removed
	if rec.SHA256 == "" || rec.OriginalDACL == "" || !rec.OwnerChanged {
		t.Fatalf("record %+v", rec)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a quarantined file can still be read: %v", err)
	}
	if err := exec.Command(cmdExe(t), "/c", "type", path).Run(); err == nil {
		t.Fatal("a quarantined file can still be opened by another process")
	}

	setQuarantineStore(qStore.path) // the record survives an agent restart
	if _, err := restoreFile(path); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "malware sample" {
		t.Fatalf("after restore: %q %v", b, err)
	}
	if _, err := restoreFile(path); err == nil {
		t.Fatal("restored twice")
	}
}

func TestQuarantineRefusesSystemFilesDirectoriesAndRoots(t *testing.T) {
	setQuarantineStore("")
	sys, _ := windows.GetSystemDirectory()
	for _, path := range []string{
		filepath.Join(sys, "drivers", "etc", "hosts"),
		t.TempDir(),
		filepath.VolumeName(sys) + `\`,
	} {
		if _, err := quarantineFile(path); err == nil {
			t.Fatalf("quarantined %s", path)
		}
	}
}

func TestIntegrityBaselineOnWindows(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("agent: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := CheckIntegrity(cfg, dir)
	if err != nil || !first.FirstRun || first.BinaryHash == "" {
		t.Fatalf("first %+v %v", first, err)
	}
	if err := os.WriteFile(cfg, []byte("agent: {name: changed}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := CheckIntegrity(cfg, dir)
	if err != nil || !again.Changed || again.ConfigMatch || !again.BinaryMatch {
		t.Fatalf("an edited config is not reported: %+v %v", again, err)
	}
}
