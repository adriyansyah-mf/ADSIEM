//go:build windows

package winsensor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

// injectEnv makes the test binary a helper that opens the process it names
// with injection rights and starts a harmless thread in it (Sleep(0)).
const injectEnv = "WINSENSOR_INJECT_PID"

func init() {
	pidText := os.Getenv(injectEnv)
	if pidText == "" {
		return
	}
	pid, _ := strconv.Atoi(pidText)
	os.Exit(injectHelper(uint32(pid)))
}

func injectHelper(pid uint32) int {
	const access = windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ
	h, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		fmt.Fprintln(os.Stderr, "OpenProcess:", err)
		return 2
	}
	defer windows.CloseHandle(h)
	// kernel32 is at the same address in every process of this boot: the
	// new thread runs Sleep(0) and ends.
	sleep := windows.NewLazySystemDLL("kernel32.dll").NewProc("Sleep").Addr()
	create := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateRemoteThread")
	th, _, err := create.Call(uintptr(h), 0, 0, sleep, 0, 0, 0)
	if th == 0 {
		fmt.Fprintln(os.Stderr, "CreateRemoteThread:", err)
		return 3
	}
	windows.WaitForSingleObject(windows.Handle(th), 5000)
	windows.CloseHandle(windows.Handle(th))
	return 0
}

// On a real Windows host (elevated): a helper opens a running ping.exe with
// injection rights and starts a thread in it; the test sets a Run value in
// its own hive. Each must come out as a Sysmon-like line.
func TestSensorReportsAccessThreadAndRegistry(t *testing.T) {
	buf := buffer.New(100000)
	s, err := Start(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	reg := StartRegistry(buf)
	defer reg.Close()
	time.Sleep(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	target := exec.CommandContext(ctx, "ping.exe", "-n", "40", "127.0.0.1")
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	defer target.Process.Kill()
	time.Sleep(2 * time.Second) // its start (and first thread) are behind us
	helper := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(), injectEnv+"="+strconv.Itoa(target.Process.Pid))
	if out, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("inject helper: %v: %s", err, out)
	}

	marker := fmt.Sprintf("siemrun%d", time.Now().UnixNano())
	run, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.SetStringValue(marker, `C:\Users\Public\`+marker+`.exe`); err != nil {
		t.Fatal(err)
	}
	defer func() { run.DeleteValue(marker); run.Close() }()

	pid := strconv.Itoa(target.Process.Pid)
	want := map[string][]string{
		"access":   {`EventID=10 `, `TargetProcessId="` + pid + `"`, `\ping.exe"`, `GrantedAccess="0x`},
		"thread":   {`EventID=8 `, `TargetProcessId="` + pid + `"`, `\ping.exe"`},
		"registry": {`EventID=13 `, `EventType="SetValue"`, `\CurrentVersion\Run\` + marker + `"`, `Details="C:\Users\Public\` + marker + `.exe"`},
	}
	got := map[string]string{}
	var seen []string
	deadline := time.Now().Add(30 * time.Second)
	for len(got) < len(want) && time.Now().Before(deadline) {
		for {
			entry, ok := buf.Pop()
			if !ok {
				break
			}
			logType, _, line := tailer.Decode(entry)
			if logType != LogTypeAccess && logType != LogTypeRegistry {
				continue
			}
			if strings.Contains(line, pid) || strings.Contains(line, marker) {
				seen = append(seen, line)
			}
			for name, parts := range want {
				match := true
				for _, p := range parts {
					match = match && strings.Contains(strings.ToLower(line), strings.ToLower(p))
				}
				if match {
					got[name] = line
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	for name := range want {
		if got[name] == "" {
			t.Errorf("no %s line; related lines seen:\n%s", name, strings.Join(seen, "\n"))
		} else {
			t.Logf("%s: %s", name, got[name])
		}
	}
	if d := s.Dropped(); d > 0 {
		t.Logf("sensor dropped %d events", d)
	}
}
