//go:build windows

package winsensor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

// loadDLLEnv makes the test binary a helper that loads the DLL it names and exits.
const loadDLLEnv = "WINSENSOR_LOAD_DLL"

func TestMain(m *testing.M) {
	if dll := os.Getenv(loadDLLEnv); dll != "" {
		h, err := windows.LoadLibrary(dll)
		if err != nil {
			fmt.Fprintln(os.Stderr, "LoadLibrary:", err)
			os.Exit(2)
		}
		windows.FreeLibrary(h)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The sensor on a real Windows host (elevated): a child process creates,
// renames and deletes a marked file, the test loads a marked DLL, and each
// comes out as a Sysmon-like line with the process attached.
func TestSensorReportsFilesAndImageLoads(t *testing.T) {
	buf := buffer.New(100000)
	s, err := Start(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	time.Sleep(2 * time.Second)

	marker := fmt.Sprintf("siemfile%d", time.Now().UnixNano())
	// TEMP is in 8.3 form on the runner (RUNNER~1); the sensor reports long paths.
	dir := longPathName(t.TempDir() + `\`)
	plain := filepath.Join(dir, marker+".txt")
	locked := plain + ".locked"
	// cmd.exe, not the test: the agent's own PID is never reported.
	script := fmt.Sprintf(`echo x> "%s" && ren "%s" "%s" && del "%s"`, plain, plain, filepath.Base(locked), locked)
	// The raw command line: exec.Command escapes quotes as \", which cmd /c
	// does not understand.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sh := exec.CommandContext(ctx, "cmd.exe")
	sh.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /c "` + script + `"`}
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	sys, _ := windows.GetSystemDirectory()
	dll := filepath.Join(dir, marker+".dll")
	data, err := os.ReadFile(filepath.Join(sys, "version.dll"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dll, data, 0o644)
	// The DLL is loaded by a child too (the agent's own loads are skipped):
	// this test binary as a helper that only calls LoadLibrary. Not rundll32:
	// a missing entry point opens a message box that nobody closes on CI.
	helper := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(), loadDLLEnv+"="+dll)
	if out, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("dll helper: %v: %s", err, out)
	}

	want := map[string][]string{
		"create": {`EventID=11 `, `FileAction="create"`, `TargetFilename="` + plain + `"`, `\cmd.exe"`},
		"rename": {`EventID=11 `, `FileAction="rename"`, `TargetFilename="` + locked + `"`, `SourceFilename="` + plain + `"`},
		"delete": {`EventID=23 `, `FileAction="delete"`, `TargetFilename="` + locked + `"`},
		"image":  {`EventID=7 `, `ImageLoaded="` + dll + `"`, `ProcessId="`},
	}
	got := map[string]string{}
	var seen []string
	deadline := time.Now().Add(20 * time.Second)
	for len(got) < len(want) && time.Now().Before(deadline) {
		for {
			entry, ok := buf.Pop()
			if !ok {
				break
			}
			logType, _, line := tailer.Decode(entry)
			if (logType != LogTypeFile && logType != LogTypeImage) || !strings.Contains(strings.ToLower(line), marker) {
				continue
			}
			seen = append(seen, line)
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
			t.Errorf("no %s line; marked lines seen:\n%s", name, strings.Join(seen, "\n"))
		} else {
			// Image comes from the process start, a different session: for a
			// short-lived child it may not have arrived yet. Logged, not required.
			t.Logf("%s (Image set: %v): %s", name, strings.Contains(got[name], ` Image="`), got[name])
		}
	}
	if d := s.Dropped(); d > 0 {
		t.Logf("sensor dropped %d events", d)
	}
}
