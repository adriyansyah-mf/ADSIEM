package ransomguard

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

const oneDrive = `C:\Program Files\Microsoft OneDrive\OneDrive.exe`

func (w *writeCase) writeAs(pid uint32, image string) {
	w.g.Observe(linsensor.FileEvent{Action: "write", Path: w.p, PID: pid, Image: image, Comm: base(image)})
}

func (w *writeCase) kills() []uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]uint32(nil), w.killed...)
}

func has(lines []string, parts ...string) bool {
	for _, l := range lines {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return true
		}
	}
	return false
}

// I1: OneDrive opens the canary, ransomware encrypts it within the same
// second. The ransomware is killed, OneDrive is not (reported as trusted).
func TestCanaryDamageKillsTheUntrustedWriterNotSync(t *testing.T) {
	w := newWriteCase(t)
	w.writeAs(70, oneDrive)
	w.writeAs(71, `C:\Users\bob\Downloads\locker.exe`)
	time.Sleep(50 * time.Millisecond)
	encryptFile(t, w.p)
	lines := w.out.wait(t, 2)
	if k := w.kills(); len(k) != 1 || k[0] != 71 {
		t.Fatalf("killed %v, want [71]; lines %q", k, lines)
	}
	if !has(lines, "detection=canary confirmed=true response=killed", "PID=71 ") ||
		!has(lines, "detection=canary confirmed=true response=trusted", "PID=70 ") {
		t.Fatalf("lines = %q", lines)
	}
}

// I1: a throwaway helper opens the canary, the real encryptor writes it:
// both untrusted writers are stopped.
func TestCanaryDamageKillsEveryUntrustedWriter(t *testing.T) {
	w := newWriteCase(t)
	w.writeAs(72, "/tmp/.x/opener")
	w.writeAs(73, "/tmp/.x/crypt")
	encryptFile(t, w.p)
	w.out.wait(t, 2)
	k := w.kills()
	if len(k) != 2 || !(k[0] == 72 && k[1] == 73 || k[0] == 73 && k[1] == 72) {
		t.Fatalf("killed %v, want 72 and 73", k)
	}
}

// I2: the writer opened the canary and waited past the read-back; the
// periodic check finds it destroyed within 2 minutes and kills that writer.
func TestPeriodicCheckKillsRecentWriters(t *testing.T) {
	w := newWriteCase(t)
	w.writeAs(74, "/tmp/.x/slow")
	w.quiet(t, "no change during the read-back")
	encryptFile(t, w.p)
	w.g.checkCanaries()
	lines := w.out.wait(t, 1)
	if !has(lines, "detection=canary confirmed=true response=killed", "PID=74 ") {
		t.Fatalf("lines = %q", lines)
	}
	// Writers older than 2 minutes are not blamed: no process, confirmed.
	w2 := newWriteCase(t)
	now := time.Now()
	w2.g.can.now = func() time.Time { return now }
	w2.writeAs(75, "/tmp/.x/old")
	w2.quiet(t, "no change")
	now = now.Add(writerWindow + time.Second)
	encryptFile(t, w2.p)
	w2.g.checkCanaries()
	if l := w2.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary_changed confirmed=true") || len(w2.kills()) != 0 {
		t.Fatalf("line = %s killed %v", l, w2.kills())
	}
}

// I2: a read blocked by a lock is retried, never taken as "unchanged".
func TestCanaryLockedReadIsRetried(t *testing.T) {
	w := newWriteCase(t)
	var mu sync.Mutex
	locked := 2
	readCanary = func(p string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if locked > 0 {
			locked--
			return nil, errors.New("The process cannot access the file because it is being used by another process.")
		}
		return os.ReadFile(p)
	}
	t.Cleanup(func() { readCanary = os.ReadFile })
	encryptFile(t, w.p)
	w.writeAs(76, "/tmp/.x/locker")
	if l := w.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary confirmed=true response=killed") {
		t.Fatalf("line = %s", l)
	}
}

// I3: a wiper (zeros) is destruction: confirmed and stopped, never a
// retirement strike, in the event path and the periodic check alike.
func TestCanaryWipeNeverRetires(t *testing.T) {
	w := newWriteCase(t)
	for i := 0; i < 2*retireAfter; i++ {
		w.g.can.plant()
		os.WriteFile(w.p, make([]byte, 4400), 0o644)
		w.writeAs(77, "/tmp/.x/wiper")
		if l := w.out.wait(t, i+1)[i]; !strings.HasPrefix(l, "detection=canary confirmed=true response=killed") {
			t.Fatalf("event %d: %s", i, l)
		}
		for deadline := time.Now().Add(time.Second); w.g.can.isCanary(w.p) && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
	}
	p := newWriteCase(t)
	for i := 0; i < 2*retireAfter; i++ {
		os.WriteFile(p.p, make([]byte, 4400), 0o644)
		p.g.checkCanaries()
		if l := p.out.wait(t, i+1)[i]; !strings.HasPrefix(l, "detection=canary_changed confirmed=true") {
			t.Fatalf("check %d: %s", i, l)
		}
	}
	for _, c := range []*writeCase{w, p} {
		c.g.can.mu.Lock()
		hits, retired := len(c.g.can.hits[c.p]), len(c.g.can.retired)
		c.g.can.mu.Unlock()
		if hits != 0 || retired != 0 {
			t.Fatalf("destruction counted toward retirement: hits %d retired %d", hits, retired)
		}
	}
}

// M1: the periodic check leaves a canary alone while a write to it is
// being followed (no double report).
func TestVerifySkipsFollowedCanary(t *testing.T) {
	w := newWriteCase(t)
	if _, ok := w.g.can.watch(w.p); !ok {
		t.Fatal("watch")
	}
	encryptFile(t, w.p)
	if bad := w.g.can.verify(); len(bad) != 0 {
		t.Fatalf("verify reported a followed canary: %+v", bad)
	}
	w.g.can.unwatch(w.p)
	if bad := w.g.can.verify(); len(bad) != 1 {
		t.Fatalf("verify = %+v", bad)
	}
}

// Canary text is adopted only when every recent writer is a trusted sync client.
func TestCanaryTextNotAdoptedWithAnUntrustedWriter(t *testing.T) {
	w := newWriteCase(t)
	w.writeAs(78, "/tmp/.x/other")
	w.writeAs(79, oneDrive)
	os.WriteFile(w.p, canaryContent(), 0o644)
	w.quiet(t, "canary text")
	w.g.checkCanaries()
	if l := w.out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=canary_changed confirmed=false") {
		t.Fatalf("line = %s", l)
	}
}
