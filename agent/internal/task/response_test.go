//go:build linux

package task

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKillRefusesPidOne(t *testing.T) {
	res, err := killProcess(1, true, 0)
	if err == nil {
		t.Fatal("pid 1 must be refused")
	}
	if res.Refused == "" {
		t.Fatalf("refusal must carry a reason: %+v", res)
	}
}

func TestKillRefusesSelf(t *testing.T) {
	res, err := killProcess(os.Getpid(), true, 0)
	if err == nil {
		t.Fatal("the agent must refuse to kill itself")
	}
	if res.Refused == "" {
		t.Fatalf("refusal must carry a reason: %+v", res)
	}
}

func TestKillRefusesInvalidPid(t *testing.T) {
	for _, pid := range []int{0, -5} {
		if _, err := killProcess(pid, false, 0); err == nil {
			t.Fatalf("pid %d must be rejected", pid)
		}
	}
}

func TestKillRefusesMissingProcess(t *testing.T) {
	res, err := killProcess(999999, false, 0)
	if err == nil {
		t.Fatal("a non-existent pid must error")
	}
	if res.Comm != "" {
		t.Fatalf("comm should be empty for a missing pid, got %q", res.Comm)
	}
}

func TestKillRefusesAncestor(t *testing.T) {
	ppid, err := parentPID(os.Getpid())
	if err != nil || ppid <= 1 {
		t.Skip("no usable parent in this environment")
	}
	res, err := killProcess(ppid, true, 0)
	if err == nil {
		t.Fatal("killing the parent would take the agent down")
	}
	if res.Refused == "" {
		t.Fatalf("refusal must carry a reason: %+v", res)
	}
}

func TestProtectedCommsCovered(t *testing.T) {
	for _, comm := range []string{"systemd", "init", "containerd", "dockerd"} {
		if _, ok := protectedComms[comm]; !ok {
			t.Errorf("%s must be protected", comm)
		}
	}
}

func TestParentPIDParsesStat(t *testing.T) {
	ppid, err := parentPID(os.Getpid())
	if err != nil {
		t.Fatalf("parentPID: %v", err)
	}
	if ppid < 0 {
		t.Fatalf("unexpected ppid %d", ppid)
	}
}

func newTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestQuarantineAndRestoreRoundTrip(t *testing.T) {
	setQuarantineStore(filepath.Join(t.TempDir(), "q.json"))
	path := newTempFile(t, "malicious payload")

	rec, err := quarantineFile(path)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if rec.SHA256 == "" {
		t.Fatal("hash must be recorded")
	}
	if rec.OriginalMode != 0o644 {
		t.Fatalf("original mode=%o want 0644", rec.OriginalMode)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file must still exist after quarantine: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0 {
		t.Fatalf("quarantined file must be mode 000, got %o", perm)
	}

	restored, err := restoreFile(path)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.OriginalMode != 0o644 {
		t.Fatalf("restore must return the mode, got %o", restored.OriginalMode)
	}

	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("mode after restore=%o want 0644", perm)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "malicious payload" {
		t.Fatalf("content changed: %q", string(data))
	}
}

func TestRestoreUnquarantinedFileFails(t *testing.T) {
	setQuarantineStore(filepath.Join(t.TempDir(), "q.json"))
	path := newTempFile(t, "x")
	if _, err := restoreFile(path); err == nil {
		t.Fatal("restoring a file that was never quarantined must fail")
	}
}

func TestQuarantineRefusesProtectedPaths(t *testing.T) {
	setQuarantineStore(filepath.Join(t.TempDir(), "q.json"))
	for _, p := range []string{"/proc/self/environ", "/sys/kernel", "/dev/null", "/"} {
		if _, err := quarantineFile(p); err == nil {
			t.Errorf("%s must be refused", p)
		}
	}
}

func TestQuarantineRefusesDirectory(t *testing.T) {
	setQuarantineStore(filepath.Join(t.TempDir(), "q.json"))
	if _, err := quarantineFile(t.TempDir()); err == nil {
		t.Fatal("directories must be refused")
	}
}

func TestQuarantineRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	setQuarantineStore(filepath.Join(dir, "q.json"))
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unsupported here")
	}
	if _, err := quarantineFile(link); err == nil {
		t.Fatal("symlinks must be refused")
	}
}

func TestQuarantineStatePersists(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "q.json")
	setQuarantineStore(statePath)

	path := newTempFile(t, "persisted")
	if _, err := quarantineFile(path); err != nil {
		t.Fatal(err)
	}

	setQuarantineStore(statePath)
	qStore.mu.Lock()
	entries := qStore.load()
	qStore.mu.Unlock()

	if _, ok := entries[path]; !ok {
		t.Fatal("quarantine record must survive a store reload")
	}
}

func TestIntegrityFirstRunCreatesBaseline(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("agent: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := CheckIntegrity(cfg, dir)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	if !rep.FirstRun {
		t.Fatal("first run must be detected")
	}
	if !rep.BinaryMatch || !rep.ConfigMatch {
		t.Fatalf("baseline run must match itself: %+v", rep)
	}
	if rep.BinaryHash == "" {
		t.Fatal("binary hash must be computed")
	}
}

func TestIntegrityDetectsConfigDrift(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("agent: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckIntegrity(cfg, dir); err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(cfg, []byte("agent: {name: tampered}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := CheckIntegrity(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FirstRun {
		t.Fatal("second run must not be treated as first")
	}
	if rep.ConfigMatch {
		t.Fatal("edited config must be reported as changed")
	}
	if !rep.BinaryMatch {
		t.Fatal("binary should be unchanged")
	}
	if !rep.Changed {
		t.Fatal("Changed must be true when anything drifted")
	}
}

func TestIntegrityResetAcceptsDrift(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckIntegrity(cfg, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rep, _ := CheckIntegrity(cfg, dir); rep.ConfigMatch {
		t.Fatal("drift expected before reset")
	}

	rep, err := ResetIntegrityBaseline(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ConfigMatch {
		t.Fatal("reset must accept the current state")
	}
}
