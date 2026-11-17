package rollback

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/ransomguard"
)

// The "ransomware" for the end-to-end tests: a child of the test binary that
// encrypts the documents already in ROLLBACK_DIR one by one (overwrite with
// random bytes, rename to .locked), slowly enough to be stopped.
func TestMain(m *testing.M) {
	if os.Getenv("ROLLBACK_HELPER") == "encrypt" {
		files, _ := filepath.Glob(filepath.Join(os.Getenv("ROLLBACK_DIR"), "doc*.txt"))
		for _, p := range files {
			data := make([]byte, 8192)
			rand.Read(data)
			os.WriteFile(p, data, 0o644)
			os.Rename(p, p+".locked")
			time.Sleep(20 * time.Millisecond)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func docContent(i int) []byte {
	return bytes.Repeat([]byte(fmt.Sprintf("document %d: quarterly figures, do not lose. ", i)), 100)
}

// sensorStart starts the OS's file sensor feeding g; stop ends it.
type sensorStart func(g *ransomguard.Guard) (stop func(), err error)

// runEndToEnd: real sensor, real RansomGuard, a real encrypting process;
// the files it encrypted before it was killed come back as they were.
// killed says the child's Wait error is the guard's kill.
func runEndToEnd(t *testing.T, root string, start sensorStart, killed func(error) bool) {
	docs := filepath.Join(root, "share")
	canaries := filepath.Join(root, "home")
	os.Mkdir(docs, 0o755)
	os.Mkdir(canaries, 0o755)
	const n = 300
	old := time.Now().Add(-time.Hour)
	for i := 0; i < n; i++ {
		p := filepath.Join(docs, fmt.Sprintf("doc%03d.txt", i))
		os.WriteFile(p, docContent(i), 0o644)
		os.Chtimes(p, old, old)
	}

	lines := make(chan string, 16)
	c := &Controller{
		Store: &Store{Dir: filepath.Join(t.TempDir(), "rollback"), Skip: DefaultSkip},
		Push:  func(_, l string) { lines <- l },
		Mode:  func() string { return ModeAuto },
		Paths: func() []string { return []string{docs} },
	}
	c.SnapshotNow()
	if l := <-lines; !strings.Contains(l, fmt.Sprintf("files=%d copied=%d", n, n)) {
		t.Fatalf("snapshot: %s", l)
	}
	time.Sleep(50 * time.Millisecond)

	var mu sync.Mutex
	var reports []string
	g := ransomguard.New(ransomguard.Options{
		Push:       func(_, l string) { mu.Lock(); reports = append(reports, l); mu.Unlock() },
		CanaryDirs: []string{canaries},
		Kill:       true,
		OnStopped:  func(s ransomguard.Stopped) { c.Restore(s.PID, s.Image, s.Since, s.Dirs) },
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.Run(ctx)
	stop, err := start(g)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	time.Sleep(2 * time.Second) // sensor sessions running

	hctx, hcancel := context.WithTimeout(ctx, 60*time.Second)
	defer hcancel()
	cmd := exec.CommandContext(hctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "ROLLBACK_HELPER=encrypt", "ROLLBACK_DIR="+docs)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	locked, _ := filepath.Glob(filepath.Join(docs, "*.locked"))
	mu.Lock()
	t.Logf("encryptor: %v after %d of %d files; guard: %v", err, len(locked), n, reports)
	mu.Unlock()
	if !killed(err) {
		t.Fatalf("the encryptor was not killed by the guard: %v", err)
	}

	var line string
	select {
	case line = <-lines:
	case <-time.After(30 * time.Second):
		t.Fatal("no rollback after the kill")
	}
	t.Log(line)
	if !strings.Contains(line, "event=ransomware_rollback") || strings.Contains(line, " restored=0 ") {
		t.Fatalf("rollback: %s", line)
	}
	for i := 0; i < n; i++ {
		p := filepath.Join(docs, fmt.Sprintf("doc%03d.txt", i))
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, docContent(i)) {
			t.Fatalf("%s not back as it was (%v)", p, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(docs, "*.locked")); len(left) != 0 {
		t.Fatalf("%d encrypted copies left in place, e.g. %s", len(left), left[0])
	}
}
