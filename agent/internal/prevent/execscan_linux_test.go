//go:build linux

package prevent

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestExecScanE2E: with the pre-exec scan on, the fanotify helper holds a
// program outside the OS's directories until the agent's scan answers; a
// program the scan refuses does not run, a clean one does, programs the OS
// owns are never sent, and turning the scan off lets everything run.
func TestExecScanE2E(t *testing.T) {
	if os.Getenv("PREVENT_E2E") != "1" {
		t.Skip("set PREVENT_E2E=1 (needs root)")
	}
	rnd := make([]byte, 6)
	rand.Read(rnd)
	tag := hex.EncodeToString(rnd)
	dir := t.TempDir()
	bad := filepath.Join(dir, "stage2.sh")
	clean := filepath.Join(dir, "clean.sh")
	writeScript(t, bad, "evil-"+tag)
	writeScript(t, clean, "ran-clean-"+tag)

	var mu sync.Mutex
	var asked []string
	scan := func(path, via string) bool {
		b, err := os.ReadFile(via) // the helper's descriptor for the held program
		mu.Lock()
		asked = append(asked, path)
		mu.Unlock()
		return err == nil && strings.Contains(string(b), "evil-"+tag)
	}
	m, err := Start(Options{Push: func(string, string) {}, ExecScan: scan})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.SetExecScan(true)

	if o, err := run(bad); err == nil || strings.Contains(o, "evil-"+tag) {
		t.Errorf("a program the scan refused ran: %v %s", err, o)
	}
	if o, err := run(clean); err != nil || !strings.Contains(o, "ran-clean-"+tag) {
		t.Errorf("a clean program was stopped: %v %s", err, o)
	}
	mu.Lock()
	for _, p := range asked {
		if strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/bin/") {
			t.Errorf("a program the OS owns was sent for a scan: %s", p)
		}
	}
	sent := strings.Join(asked, " ")
	mu.Unlock()
	if !strings.Contains(sent, bad) || !strings.Contains(sent, clean) {
		t.Errorf("asked about %q", sent)
	}

	m.SetExecScan(false)
	if o, err := run(bad); err != nil || !strings.Contains(o, "evil-"+tag) {
		t.Errorf("scan off: the program must run: %v %s", err, o)
	}
}

func TestScanAsksMatchAnswersToRequests(t *testing.T) {
	var mu sync.Mutex
	var sent []scanRequest
	a := newScanAsks(func(v any) {
		if d, ok := v.(helperDecision); ok && d.Scan != nil {
			mu.Lock()
			sent = append(sent, *d.Scan)
			mu.Unlock()
		}
	})
	go func() { // the agent answers the second request first
		for {
			mu.Lock()
			n := len(sent)
			mu.Unlock()
			if n == 2 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		a.answer(scanReply{ID: sent[1].ID, Block: true})
		a.answer(scanReply{ID: sent[0].ID, Block: false})
	}()
	type res struct{ block, ok bool }
	r1, r2 := make(chan res, 1), make(chan res, 1)
	go func() { b, ok := a.ask("/tmp/a", 7, 100); r1 <- res{b, ok} }()
	time.Sleep(20 * time.Millisecond)
	go func() { b, ok := a.ask("/tmp/b", 8, 101); r2 <- res{b, ok} }()
	if got := <-r1; got.block || !got.ok {
		t.Errorf("first: %+v", got)
	}
	if got := <-r2; !got.block || !got.ok {
		t.Errorf("second: %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if sent[0].Via != "/proc/"+itoa(os.Getpid())+"/fd/7" || sent[0].Path != "/tmp/a" || sent[0].PID != 100 {
		t.Errorf("request: %+v", sent[0])
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestScanAskWithoutAnswerAllows(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the timeout")
	}
	a := newScanAsks(func(any) {})
	start := time.Now()
	block, answered := a.ask("/tmp/x", 3, 1)
	if block || answered {
		t.Fatalf("no answer: block=%v answered=%v", block, answered)
	}
	if d := time.Since(start); d < execScanTimeout || d > execScanTimeout+2*time.Second {
		t.Fatalf("waited %v", d)
	}
}

func TestClientAnswersAScanRequestOnStdin(t *testing.T) {
	r, w := io.Pipe()
	c := &fanClient{stdin: w, scan: func(path, via string) bool { return path == "/tmp/bad" && via == "/proc/1/fd/9" }}
	go c.answer(scanRequest{ID: 42, Path: "/tmp/bad", Via: "/proc/1/fd/9", PID: 5})
	line, err := bufio.NewReader(r).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var msg helperPolicy
	if err := json.Unmarshal(line, &msg); err != nil || msg.ScanReply == nil {
		t.Fatalf("line %s: %v", line, err)
	}
	if msg.ScanReply.ID != 42 || !msg.ScanReply.Block || len(msg.Rules) != 0 {
		t.Fatalf("reply: %+v", msg)
	}
}

func TestGatedCarriesTheExecScanSwitch(t *testing.T) {
	m := &Manager{opts: Options{ExecScan: func(string, string) bool { return false }}}
	p, _ := Compile(nil)
	if m.gated(p).scanExec {
		t.Fatal("off by default")
	}
	m.scanExec = true
	if !m.gated(p).scanExec {
		t.Fatal("on")
	}
	m.off = true // prevention off: the scan has its own switch
	if g := m.gated(p); !g.scanExec || !g.off {
		t.Fatalf("prevention off keeps the scan: %+v", g)
	}
	m.opts.ExecScan = nil
	if m.gated(p).scanExec {
		t.Fatal("no scanner, no scan")
	}
}
