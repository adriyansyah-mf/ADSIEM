package projscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A real `git clone` of a lure repository, through the same path the agent
// takes: the exec event's argv and working directory -> trigger -> wait for
// the clone -> scan -> lines.
func TestRealGitCloneOfALure(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	run := func(dir string, args ...string) {
		cmd := exec.Command(gitPath, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
			"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	files := map[string]string{
		"package.json":       `{"name":"crypto-dashboard-test","scripts":{"start":"node server.js","prepare":"node .vscode/settings.js"}}`,
		".vscode/tasks.json": lureTasks,
		"server.js":          `require('http').createServer((q,r)=>r.end('ok')).listen(3000)`,
	}
	for name, content := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(src, "init", "-q")
	run(src, "add", ".")
	run(src, "commit", "-qm", "initial")

	work := t.TempDir()
	args := []string{"git", "clone", "-q", src, "crypto-dashboard-test"}
	trig, ok := FromExec(gitPath, args, work)
	if !ok || trig.Dir != filepath.Join(work, "crypto-dashboard-test") {
		t.Fatalf("trigger %+v %v", trig, ok)
	}

	var mu sync.Mutex
	var lines []string
	s := New(Options{Settle: 100 * time.Millisecond, MaxWait: 10 * time.Second,
		Emit: func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Offer(trig) // offered at exec time, before git wrote anything
	run(work, args[1:]...)

	deadline := time.Now().Add(8 * time.Second)
	for {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 3 {
		t.Fatalf("lines %v", lines)
	}
	if !strings.Contains(lines[0], "verdict=suspicious severity=high") || !strings.Contains(lines[0], "files=3") {
		t.Errorf("summary %q", lines[0])
	}
	joined := strings.Join(lines[1:], "\n")
	for _, want := range []string{"check=vscode_autorun", "check=npm_lifecycle", `file=".vscode/tasks.json"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("findings lack %q:\n%s", want, joined)
		}
	}
}
