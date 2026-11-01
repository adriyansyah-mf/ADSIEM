//go:build windows

package winsensor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

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
	if out, err := exec.Command("cmd.exe", "/c", script).CombinedOutput(); err != nil {
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
	// rundll32 loads it and fails to find the entry point, which is fine.
	exec.Command(filepath.Join(sys, "rundll32.exe"), dll+",SiemNoSuchEntry").Run()

	want := map[string][]string{
		"create": {`EventID=11 `, `FileAction="create"`, `TargetFilename="` + plain + `"`, `cmd.exe"`},
		"rename": {`EventID=11 `, `FileAction="rename"`, `TargetFilename="` + locked + `"`, `SourceFilename="` + plain + `"`},
		"delete": {`EventID=23 `, `FileAction="delete"`, `TargetFilename="` + locked + `"`},
		"image":  {`EventID=7 `, `ImageLoaded="` + dll + `"`, `rundll32.exe"`},
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
			t.Logf("%s: %s", name, got[name])
		}
	}
	if d := s.Dropped(); d > 0 {
		t.Logf("sensor dropped %d events", d)
	}
}
