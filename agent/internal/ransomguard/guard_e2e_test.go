//go:build linux

package ransomguard

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// End to end with the real eBPF sensor: needs root, BTF and tracefs. Run
// with RANSOM_E2E=1 (see docs/operations/anti-ransomware.md). The
// "ransomware" is a child process of this test binary; the sensor
// ignores the test process itself.

func TestMain(m *testing.M) {
	switch os.Getenv("RANSOM_HELPER") {
	case "encrypt":
		// Encrypt-and-rename like ransomware, slowly enough to be stopped.
		dir := os.Getenv("RANSOM_DIR")
		for i := 0; i < 400; i++ {
			p := filepath.Join(dir, fmt.Sprintf("doc%03d.txt", i))
			data := make([]byte, 8192)
			rand.Read(data)
			os.WriteFile(p, data, 0o644)
			os.Rename(p, p+".locked")
			time.Sleep(20 * time.Millisecond)
		}
		os.WriteFile(filepath.Join(dir, "FINISHED"), nil, 0o644)
		os.Exit(0)
	case "canary":
		os.WriteFile(os.Getenv("RANSOM_CANARY"), []byte("encrypted"), 0o644)
		time.Sleep(10 * time.Second) // waits to be killed
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(t *testing.T, kind string, env ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), "RANSOM_HELPER="+kind), env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func killedBySignal(err error) bool {
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

// TestFalsePositives watches the host's real activity with kill off:
// RANSOM_FP=10m -test.run TestFalsePositives (as root).
func TestFalsePositives(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("RANSOM_FP"))
	if err != nil {
		t.Skip("set RANSOM_FP to a duration")
	}
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{t.TempDir()}})
	events := 0
	sensor, err := linsensor.Start(linsensor.Options{Push: func(string, string) {}, OnFile: func(e linsensor.FileEvent) {
		events++
		g.Observe(e)
	}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(d)
	sensor.Stop()
	t.Logf("%d file events in %v, %d detections", events, d, len(out.lines))
	for _, l := range out.lines {
		t.Log(l)
	}
}

func TestRansomwareEndToEnd(t *testing.T) {
	if os.Getenv("RANSOM_E2E") != "1" {
		t.Skip("set RANSOM_E2E=1 (needs root, BTF and tracefs)")
	}
	root := t.TempDir()
	canaryDir := filepath.Join(root, "home")
	data := filepath.Join(root, "share")
	os.Mkdir(canaryDir, 0o755)
	os.Mkdir(data, 0o755)

	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{canaryDir}, Kill: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	sensor, err := linsensor.Start(linsensor.Options{Push: func(string, string) {}, OnFile: g.Observe})
	if err != nil {
		t.Fatal(err)
	}
	defer sensor.Stop()
	time.Sleep(500 * time.Millisecond) // canaries planted

	// Heuristic: mass rename to .locked of high-entropy files.
	enc := helper(t, "encrypt", "RANSOM_DIR="+data)
	err = enc.Wait()
	if !killedBySignal(err) {
		t.Fatalf("encryptor not killed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "FINISHED")); err == nil {
		t.Fatal("encryptor finished its run")
	}
	locked, _ := filepath.Glob(filepath.Join(data, "*.locked"))
	t.Logf("encryptor stopped after %d of 400 files", len(locked))
	lines := out.wait(t, 1)
	if !strings.HasPrefix(lines[0], "detection=extension_change confirmed=true response=killed") ||
		!strings.Contains(lines[0], `Extension=".locked"`) || !strings.Contains(lines[0], fmt.Sprintf("PID=%d", enc.Process.Pid)) {
		t.Fatalf("line = %s", lines[0])
	}

	// Canary: one write is enough.
	canary := filepath.Join(canaryDir, "!siem-canary.pdf")
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("canary not planted: %v", err)
	}
	cw := helper(t, "canary", "RANSOM_CANARY="+canary)
	start := time.Now()
	if err := cw.Wait(); !killedBySignal(err) {
		t.Fatalf("canary writer not killed: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("canary writer killed only after %v", d)
	}
	lines = out.wait(t, 2)
	if !strings.HasPrefix(lines[1], "detection=canary confirmed=true response=killed") || !strings.Contains(lines[1], "FileAction=create") {
		t.Fatalf("line = %s", lines[1])
	}
}
