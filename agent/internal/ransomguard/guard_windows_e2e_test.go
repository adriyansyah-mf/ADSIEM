//go:build windows

package ransomguard

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/linsensor"
	"github.com/siem-platform/agent/internal/winsensor"
)

// End to end on an elevated Windows host with the real ETW sensor (the
// native-evidence CI job sets SIEM_NATIVE_EVENTLOG=1). The "ransomware" is
// a child of this test binary: the sensor never reports the agent's own PID.

func TestMain(m *testing.M) {
	switch os.Getenv("RANSOM_HELPER") {
	case "encrypt":
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
		os.Remove(os.Getenv("RANSOM_CANARY"))
		time.Sleep(15 * time.Second) // waits to be killed
		os.Exit(0)
	case "inplace":
		// Encrypt each file over itself: open, read, write random bytes
		// back at offset 0. No rename, no delete, no new file.
		files, _ := filepath.Glob(filepath.Join(os.Getenv("RANSOM_DIR"), "*", "*.docx"))
		for _, p := range files {
			overwrite(p)
			time.Sleep(20 * time.Millisecond)
		}
		os.WriteFile(filepath.Join(os.Getenv("RANSOM_DIR"), "FINISHED"), nil, 0o644)
		os.Exit(0)
	case "canary-overwrite":
		overwrite(os.Getenv("RANSOM_CANARY"))
		time.Sleep(15 * time.Second) // waits to be killed
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// overwrite encrypts p in place: same file, same size, random bytes.
func overwrite(p string) {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}
	data := make([]byte, info.Size())
	f.ReadAt(data, 0)
	rand.Read(data)
	f.WriteAt(data, 0)
}

func helperWin(t *testing.T, ctx context.Context, kind string, env ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), "RANSOM_HELPER="+kind), env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func longPath(t *testing.T, p string) string {
	in, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		t.Fatalf("GetLongPathName(%s): %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// terminated: TerminateProcess(h, 1) by the guard, not a normal exit (0) or
// the context's kill.
func terminated(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 1
}

func TestRansomwareEndToEndWindows(t *testing.T) {
	if os.Getenv("SIEM_NATIVE_EVENTLOG") != "1" {
		t.Skip("native Windows test: set SIEM_NATIVE_EVENTLOG=1 in an elevated prompt")
	}
	// TEMP is in 8.3 form on the runner (RUNNER~1) and ETW reports long
	// paths; the real canary dirs come from a glob, which gives long names.
	root := longPath(t, t.TempDir())
	canaryDir := filepath.Join(root, "home")
	data := filepath.Join(root, "share")
	os.Mkdir(canaryDir, 0o755)
	os.Mkdir(data, 0o755)

	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{canaryDir}, Kill: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	sensor, err := winsensor.StartWith(buffer.New(100000), winsensor.Options{OnFile: func(e winsensor.FileEvent) {
		g.Observe(linsensor.FileEvent{Time: e.Time, PID: e.PID, PPID: e.PPID, Image: e.Image,
			Comm: filepath.Base(e.Image), Action: e.Action, Path: e.Path, From: e.From})
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer sensor.Stop()
	time.Sleep(2 * time.Second) // sessions running, canaries planted

	hctx, hcancel := context.WithTimeout(ctx, 60*time.Second)
	defer hcancel()

	// Heuristic: mass rename to .locked of high-entropy files.
	enc := helperWin(t, hctx, "encrypt", "RANSOM_DIR="+data)
	err = enc.Wait()
	locked, _ := filepath.Glob(filepath.Join(data, "*.locked"))
	t.Logf("encryptor: %v after %d of 400 files", err, len(locked))
	if !terminated(err) {
		t.Errorf("encryptor not terminated by the guard: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "FINISHED")); err == nil {
		t.Error("encryptor finished its run")
	}
	lines := out.wait(t, 1)
	if !strings.HasPrefix(lines[0], "detection=extension_change confirmed=true response=killed") ||
		!strings.Contains(lines[0], `Extension=".locked"`) || !strings.Contains(lines[0], fmt.Sprintf("PID=%d", enc.Process.Pid)) {
		t.Errorf("line = %s", lines[0])
	}

	// Canary: one delete is enough.
	canary := filepath.Join(canaryDir, ".siem-canary.pdf")
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("canary not planted: %v", err)
	}
	start := time.Now()
	cw := helperWin(t, hctx, "canary", "RANSOM_CANARY="+canary)
	err = cw.Wait()
	t.Logf("canary deleter: %v after %v", err, time.Since(start))
	if !terminated(err) {
		t.Errorf("canary deleter not terminated by the guard: %v", err)
	}
	lines = out.wait(t, 2)
	found := false
	for _, l := range lines[1:] {
		found = found || (strings.HasPrefix(l, "detection=canary confirmed=true response=killed") && strings.Contains(l, "FileAction=delete"))
	}
	if !found {
		t.Errorf("no canary kill line: %q", lines)
	}

	// In place: pre-existing documents overwritten with random bytes, no
	// rename. Under the user profile, not TEMP: in-place writes under
	// AppData\Local (TEMP) and other cache paths do not count.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	docs, err := os.MkdirTemp(home, "siem-ransom-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(docs) })
	docs = longPath(t, docs)
	const docCount = 400
	for i := 0; i < docCount; i++ {
		sub := filepath.Join(docs, fmt.Sprintf("folder%d", i%4))
		os.MkdirAll(sub, 0o755)
		text := strings.Repeat(fmt.Sprintf("quarterly report %d, nothing to see here. ", i), 200)
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("report%03d.docx", i)), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second) // the test's own writes are not reported; let the sensor settle
	ip := helperWin(t, hctx, "inplace", "RANSOM_DIR="+docs)
	err = ip.Wait()
	t.Logf("in-place encryptor: %v", err)
	if !terminated(err) {
		t.Errorf("in-place encryptor not terminated by the guard: %v", err)
	}
	if _, err := os.Stat(filepath.Join(docs, "FINISHED")); err == nil {
		t.Error("in-place encryptor finished its run")
	}
	want := fmt.Sprintf("PID=%d ", ip.Process.Pid)
	if l := waitLine(t, &out, func(l string) bool {
		return strings.HasPrefix(l, "detection=inplace_modify confirmed=true response=killed") && strings.Contains(l, want)
	}); l == "" {
		t.Errorf("no inplace_modify kill line: %q", out.wait(t, 1))
	}

	// A canary overwritten in place (Kernel-File write, no rename or delete).
	canary = filepath.Join(canaryDir, ".siem-canary.docx")
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("canary not planted: %v", err)
	}
	co := helperWin(t, hctx, "canary-overwrite", "RANSOM_CANARY="+canary)
	err = co.Wait()
	t.Logf("canary overwriter: %v", err)
	if !terminated(err) {
		t.Errorf("canary overwriter not terminated by the guard: %v", err)
	}
	want = fmt.Sprintf("PID=%d ", co.Process.Pid)
	if l := waitLine(t, &out, func(l string) bool {
		return strings.HasPrefix(l, "detection=canary confirmed=true response=killed") &&
			strings.Contains(l, "FileAction=write") && strings.Contains(l, want)
	}); l == "" {
		t.Errorf("no canary write kill line: %q", out.wait(t, 1))
	}
}

// waitLine waits up to 5 s for a line that match accepts.
func waitLine(t *testing.T, s *sink, match func(string) bool) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		s.mu.Lock()
		for _, l := range s.lines {
			if match(l) {
				s.mu.Unlock()
				return l
			}
		}
		s.mu.Unlock()
	}
	return ""
}
