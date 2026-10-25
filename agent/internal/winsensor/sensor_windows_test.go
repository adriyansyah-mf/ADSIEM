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

// The sensor on a real Windows host (elevated): a marked command line comes
// out as one Sysmon-like process creation line with both halves joined.
func TestSensorReportsAProcessWithBothHalves(t *testing.T) {
	buf := buffer.New(10000)
	s, err := Start(buf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	time.Sleep(2 * time.Second)

	marker := fmt.Sprintf("siem-sensor-%d", time.Now().UnixNano())
	if err := exec.Command("cmd.exe", "/c", "echo", marker).Run(); err != nil {
		t.Fatal(err)
	}
	sys, _ := windows.GetSystemDirectory()
	self, _ := os.Executable()

	var got string
	deadline := time.Now().Add(15 * time.Second)
	for got == "" && time.Now().Before(deadline) {
		for {
			entry, ok := buf.Pop()
			if !ok {
				break
			}
			logType, _, line := tailer.Decode(entry)
			if logType == LogTypeProcess && strings.Contains(line, marker) {
				got = line
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got == "" {
		t.Fatal("no process line for the marked command")
	}
	t.Logf("line: %s", got)
	for _, want := range []string{
		`Image="` + filepath.Join(sys, "cmd.exe") + `"`,
		`CommandLine="cmd.exe /c echo ` + marker + `"`,
		`ParentImage="` + self + `"`,
		`User="`, `IntegrityLevel="High"`,
	} {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			t.Errorf("missing %s", want)
		}
	}
}
