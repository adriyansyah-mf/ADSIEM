package tailer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/buffer"
)

// copytruncate rotation keeps the inode and empties the file; the tailer must
// keep reading the lines written after it.
func TestTailSurvivesCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site.log")
	appendLine := func(s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(s + "\n")
		f.Close()
	}
	appendLine("old line that is long enough to make the file bigger than what follows")

	buf := buffer.New(100)
	stop := make(chan struct{})
	defer close(stop)
	go Tail(path, "nginx_access_combined", buf, stop)

	got := func(want string) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if entry, ok := buf.Pop(); ok {
				if _, _, line := Decode(entry); line == want {
					return
				}
				continue
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("line %q never tailed", want)
	}

	time.Sleep(300 * time.Millisecond) // tailer opened the file and sought to EOF
	appendLine("before rotation")
	got("before rotation")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLine("after rotation")
	got("after rotation")
}
