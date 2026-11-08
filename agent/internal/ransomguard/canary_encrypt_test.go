package ransomguard

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/siem-platform/agent/internal/linsensor"
)

// encryptFile overwrites p in place with random bytes, as ransomware does.
func encryptFile(t *testing.T, p string) {
	t.Helper()
	data := make([]byte, 4400)
	rand.Read(data)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCanaryContentLooksEncrypted(t *testing.T) {
	random := make([]byte, 4400)
	rand.Read(random)
	partly := append(append([]byte{}, random[:1024]...), canaryContent()[1024:]...) // first 1 KB encrypted
	for name, c := range map[string]struct {
		data []byte
		want bool
	}{
		"canary":            {canaryContent(), false},
		"text rewrite":      {[]byte(strings.Repeat("deployed by ci\n", 300)), false},
		"tiny":              {[]byte("encrypted"), false},
		"empty":             {nil, false},
		"random":            {random, true},
		"head encrypted":    {partly, true},
		"zip (legit, high)": {append([]byte("PK\x03\x04"), random[4:]...), false},
	} {
		if got := looksEncrypted(c.data); got != c.want {
			t.Errorf("%s: looksEncrypted = %t, want %t", name, got, c.want)
		}
	}
}

// A process that encrypts a canary in place is stopped every time and the
// canary never retires: retirement is for tools that rewrite it in clear.
func TestGuardEncryptedCanaryNeverRetires(t *testing.T) {
	dir := t.TempDir()
	var out sink
	var mu sync.Mutex
	kills := 0
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, CanaryNames: []string{".c.pdf"}, Kill: true})
	g.response = func(uint32) (int, error) { mu.Lock(); kills++; mu.Unlock(); return 1, nil }
	p := filepath.Join(dir, ".c.pdf")
	for i := 0; i < 2*retireAfter; i++ {
		if g.can.plant(); !g.can.isCanary(p) {
			t.Fatalf("run %d: canary not planted (retired?)", i)
		}
		encryptFile(t, p)
		g.Observe(linsensor.FileEvent{Action: "write", Path: p, PID: 60, Image: `C:\Users\bob\Downloads\locker.exe`, Comm: "locker.exe"})
		lines := out.wait(t, i+1)
		if !strings.HasPrefix(lines[i], "detection=canary confirmed=true response=killed") {
			t.Fatalf("run %d: %s", i, lines[i])
		}
		g.can.mu.Lock()
		struck := len(g.can.hits[p])
		g.can.mu.Unlock()
		if struck != 0 {
			t.Fatalf("run %d: an encrypted canary counted toward retirement (%d)", i, struck)
		}
	}
	for _, l := range out.wait(t, 2*retireAfter) {
		if strings.Contains(l, "canary_retired") {
			t.Fatalf("retired: %s", l)
		}
	}
}

func checkGuard(t *testing.T, isolate func() error) (*Guard, *sink, string) {
	t.Helper()
	dir := t.TempDir()
	var out sink
	g := New(Options{Push: out.push, CanaryDirs: []string{dir}, CanaryNames: []string{".c.docx"}, Kill: true, Isolate: isolate})
	g.response = func(uint32) (int, error) { t.Error("nothing to kill without a process"); return 0, nil }
	g.can.plant()
	return g, &out, filepath.Join(dir, ".c.docx")
}

// The periodic check found a canary encrypted and no process is known (an
// in-place overwrite before this agent saw writes on Windows): confirmed,
// so the critical rule fires, and the host is isolated when asked for.
func TestPeriodicCheckEncryptedCanaryIsolates(t *testing.T) {
	isolated := 0
	g, out, p := checkGuard(t, func() error { isolated++; return nil })
	for i := 0; i < 2*retireAfter; i++ {
		encryptFile(t, p)
		g.checkCanaries()
		l := out.wait(t, i+1)[i]
		want := "detection=canary_changed confirmed=true response=isolated Canary=" + kv(p) + " Isolated=true"
		if l != want {
			t.Fatalf("run %d:\n got %s\nwant %s", i, l, want)
		}
		if !g.can.isCanary(p) {
			t.Fatalf("run %d: canary not replanted (retired)", i)
		}
	}
	if isolated != 2*retireAfter {
		t.Fatalf("isolated %d times", isolated)
	}
}

func TestPeriodicCheckEncryptedCanaryWithoutIsolate(t *testing.T) {
	g, out, p := checkGuard(t, nil)
	encryptFile(t, p)
	g.checkCanaries()
	if l := out.wait(t, 1)[0]; l != "detection=canary_changed confirmed=true response=none Canary="+kv(p)+" Isolated=false" {
		t.Fatalf("line = %s", l)
	}
}

// A tool rewriting the canary in clear: unconfirmed, retired after the third
// change in a day, as before.
func TestPeriodicCheckBenignRewriteRetires(t *testing.T) {
	g, out, p := checkGuard(t, func() error { t.Error("a benign rewrite isolated the host"); return nil })
	for i := 0; i < retireAfter; i++ {
		os.WriteFile(p, []byte(strings.Repeat("rewritten by a sync tool\n", 100)), 0o644)
		g.checkCanaries()
	}
	lines := out.wait(t, retireAfter+1)
	for i := 0; i < retireAfter; i++ {
		if lines[i] != "detection=canary_changed confirmed=false response=none Canary="+kv(p)+" Isolated=false" {
			t.Fatalf("line %d = %s", i, lines[i])
		}
	}
	if !strings.HasPrefix(lines[retireAfter], "detection=canary_retired confirmed=false") || g.can.isCanary(p) {
		t.Fatalf("not retired: %q", lines)
	}
}
