//go:build windows

package prevent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/winsensor"
)

func TestWindowsRulesFoldCaseAndSeparators(t *testing.T) {
	sys, _ := windows.GetSystemDirectory()
	p, errs := Compile([]Rule{
		{ID: "1", Name: "tool", RuleType: TypePath, Value: `C:\Tools\EVIL.exe`, Action: ActionBlock},
		{ID: "2", Name: "public", RuleType: TypeDir, Value: `C:\Users\Public`, Action: ActionDetect},
		{ID: "3", Name: "office shell", RuleType: TypeParent, Parent: "WINWORD.EXE", Value: "cmd.exe", Action: ActionDetect},
		{ID: "4", Name: "shell", RuleType: TypePath, Value: filepath.Join(sys, "cmd.exe"), Action: ActionBlock},
		{ID: "5", Name: "linux path", RuleType: TypePath, Value: "/usr/bin/nc", Action: ActionBlock},
	})
	if len(errs) != 2 { // the shell kept detect-only, the Linux path refused
		t.Fatalf("errs = %v", errs)
	}
	match := func(path, parent string) string {
		if c := p.Match(Exec{Path: path, Parent: parent}, false); c != nil {
			return c.Name
		}
		return ""
	}
	if got := match(`c:\tools\evil.EXE`, ""); got != "tool" {
		t.Errorf("path rule ignoring case: %q", got)
	}
	if got := match(`C:\Users\Public\x.exe`, ""); got != "public" {
		t.Errorf("dir rule: %q", got)
	}
	if got := match(`C:\Users\PublicX\x.exe`, ""); got != "" {
		t.Errorf("dir rule matched a sibling: %q", got)
	}
	if got := match(filepath.Join(sys, "CMD.EXE"), `C:\Program Files\Microsoft Office\root\Office16\winword.exe`); got != "office shell" && got != "shell" {
		t.Errorf("parent rule: %q", got)
	}
	for _, c := range p.Rules {
		if c.Name == "shell" && c.block {
			t.Error("a block rule on System32\\cmd.exe must stay detect-only")
		}
	}
}

type lines struct {
	mu sync.Mutex
	l  []string
}

func (s *lines) push(_, line string) { s.mu.Lock(); s.l = append(s.l, line); s.mu.Unlock() }

func (s *lines) find(t *testing.T, parts ...string) string {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		s.mu.Lock()
		for _, l := range s.l {
			ok := true
			for _, p := range parts {
				ok = ok && strings.Contains(l, p)
			}
			if ok {
				s.mu.Unlock()
				return l
			}
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("no decision with %q; got %q", parts, s.l)
	return ""
}

func longPath(t *testing.T, p string) string {
	in, _ := windows.UTF16PtrFromString(p)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	return windows.UTF16ToString(buf[:n])
}

// End to end on an elevated Windows host (the native-evidence job sets
// SIEM_NATIVE_EVENTLOG=1): the real ETW sensor feeds the engine; a copy of
// ping under a block rule is terminated long before it finishes, a copy under
// a detect rule runs to the end.
func TestWindowsKillOnExecEndToEnd(t *testing.T) {
	if os.Getenv("SIEM_NATIVE_EVENTLOG") != "1" {
		t.Skip("native Windows test: set SIEM_NATIVE_EVENTLOG=1 in an elevated prompt")
	}
	var out lines
	m, err := Start(Options{Push: out.push})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	dir := longPath(t, t.TempDir()) // ETW reports long paths; TEMP is 8.3 on the runner
	sys, _ := windows.GetSystemDirectory()
	ping, err := os.ReadFile(filepath.Join(sys, "PING.EXE"))
	if err != nil {
		t.Fatal(err)
	}
	blocked, detected := filepath.Join(dir, "siem-blocked.exe"), filepath.Join(dir, "siem-detected.exe")
	os.WriteFile(blocked, ping, 0o755)
	os.WriteFile(detected, ping, 0o755)
	m.Apply("e2e", []Rule{
		{ID: "b", Name: "e2e block", RuleType: TypePath, Value: blocked, Action: ActionBlock},
		{ID: "d", Name: "e2e detect", RuleType: TypePath, Value: detected, Action: ActionDetect},
	})
	sensor, err := winsensor.StartWith(buffer.New(100000), winsensor.Options{OnProcess: func(p winsensor.ProcessStart) {
		m.ObserveExec(ProcessStart{PID: p.PID, PPID: p.PPID, Image: p.Image, ParentImage: p.ParentImage})
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer sensor.Stop()
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	err = exec.CommandContext(ctx, blocked, "-n", "30", "127.0.0.1").Run() // ~29 s if left alone
	took := time.Since(start)
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || took > 15*time.Second {
		t.Fatalf("blocked copy: %v after %v, want terminated (exit 1) within seconds", err, took)
	}
	t.Logf("blocked copy terminated after %v", took)
	t.Log(out.find(t, "action=terminated", `rule="e2e block"`, "engine=etw"))

	if err := exec.CommandContext(ctx, detected, "-n", "2", "127.0.0.1").Run(); err != nil {
		t.Fatalf("detect-only copy did not run to the end: %v", err)
	}
	t.Log(out.find(t, "action=detected", `rule="e2e detect"`))
}
