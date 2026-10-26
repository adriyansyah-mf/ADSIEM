//go:build linux

package prevent

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// End-to-end against the running kernel: needs root and, for the LSM
// run, "bpf" in /sys/kernel/security/lsm. Run with PREVENT_E2E=1 (see
// docs/operations/exec-prevention.md). Both engines act host-wide, so
// every rule targets only files this test creates.

func TestMain(m *testing.M) {
	if IsHelper() {
		os.Exit(RunHelper()) // the fanotify engine runs in a copy of this binary
	}
	os.Exit(m.Run())
}

type lines struct {
	mu  sync.Mutex
	got []string
}

func (l *lines) push(_, line string) {
	l.mu.Lock()
	l.got = append(l.got, line)
	l.mu.Unlock()
}

func (l *lines) has(parts ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range l.got {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(g, p)
		}
		if ok {
			return true
		}
	}
	return false
}

func writeScript(t *testing.T, path, marker string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// run executes path from a shell, so the exec is not the test process's.
func run(path string) (string, error) {
	out, err := exec.Command("sh", "-c", path).CombinedOutput()
	return string(out), err
}

func e2e(t *testing.T, fanotifyOnly bool) {
	if os.Getenv("PREVENT_E2E") != "1" {
		t.Skip("set PREVENT_E2E=1 (needs root)")
	}
	noLSM = fanotifyOnly
	defer func() { noLSM = false }()
	if !fanotifyOnly && !bpfLSMEnabled() {
		t.Skip("kernel without BPF LSM")
	}

	rnd := make([]byte, 6)
	rand.Read(rnd)
	tag := hex.EncodeToString(rnd)
	dir := t.TempDir()
	blockedDir := filepath.Join(dir, "blocked")
	os.Mkdir(blockedDir, 0o755)
	os.Mkdir(filepath.Join(blockedDir, "deep"), 0o755)

	inDir := filepath.Join(blockedDir, "deep", "x.sh")
	watched := filepath.Join(dir, "watched.sh")
	child := filepath.Join(dir, "child-"+tag)
	hashed := filepath.Join(dir, "hashed.sh")
	clean := filepath.Join(dir, "clean.sh")
	writeScript(t, inDir, "ran-in-dir-"+tag)
	writeScript(t, watched, "ran-watched-"+tag)
	writeScript(t, child, "ran-child-"+tag)
	writeScript(t, hashed, "ran-hashed-"+tag)
	writeScript(t, clean, "ran-clean-"+tag)
	sum, err := hashFile(hashed, maxHashBytes)
	if err != nil {
		t.Fatal(err)
	}

	var out lines
	m, err := Start(Options{Push: out.push})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.Apply("e2e", []Rule{
		{ID: "r1", Name: "no exec in blocked", RuleType: TypeDir, Value: blockedDir, Action: ActionBlock},
		{ID: "r2", Name: "watch script", RuleType: TypePath, Value: watched, Action: ActionDetect},
		{ID: "r3", Name: "shell starts child", RuleType: TypeParent, Parent: "sh,dash,bash", Value: filepath.Base(child), Action: ActionBlock},
		{ID: "r4", Name: "known bad hash", RuleType: TypeHash, Value: sum, Action: ActionBlock},
	})
	engine := "lsm"
	if fanotifyOnly {
		engine = "fanotify"
	}

	if o, err := run(inDir); err == nil || strings.Contains(o, "ran-in-dir-"+tag) {
		t.Errorf("exec below a blocked dir ran: %v %s", err, o)
	}
	if o, err := run(watched); err != nil || !strings.Contains(o, "ran-watched-"+tag) {
		t.Errorf("a detect rule must not stop the program: %v %s", err, o)
	}
	if o, err := run(child); err == nil || strings.Contains(o, "ran-child-"+tag) {
		t.Errorf("parent rule did not block: %v %s", err, o)
	}
	if o, err := run(hashed); err == nil || strings.Contains(o, "ran-hashed-"+tag) {
		t.Errorf("hash rule did not block: %v %s", err, o)
	}
	if o, err := run(clean); err != nil || !strings.Contains(o, "ran-clean-"+tag) {
		t.Errorf("an unmatched program was stopped: %v %s", err, o)
	}

	deadline := time.Now().Add(5 * time.Second)
	want := [][]string{
		{"action=blocked", `rule="no exec in blocked"`, "rule_type=dir", "engine=" + engine, `Image="` + inDir + `"`},
		{"action=detected", `rule="watch script"`, "engine=" + engine, `Image="` + watched + `"`},
		{"action=blocked", `rule="shell starts child"`, "rule_type=parent", "engine=" + engine},
		{"action=blocked", `rule="known bad hash"`, "engine=fanotify", "SHA256=" + sum},
	}
	for _, w := range want {
		for !out.has(w...) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if !out.has(w...) {
			out.mu.Lock()
			t.Errorf("no decision with %q; got:\n%s", w, strings.Join(out.got, "\n"))
			out.mu.Unlock()
		}
	}
	// Turning the rules off lets everything run again.
	m.Apply("empty", nil)
	if o, err := run(inDir); err != nil || !strings.Contains(o, "ran-in-dir-"+tag) {
		t.Errorf("still blocked after the rules were removed: %v %s", err, o)
	}
}

func TestPreventLSM(t *testing.T)          { e2e(t, false) }
func TestPreventFanotifyOnly(t *testing.T) { e2e(t, true) }
