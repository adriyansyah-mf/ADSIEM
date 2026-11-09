package ransomguard

import (
	"fmt"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// Ransomware walks a tree folder by folder. With 100 documents per folder
// the first 4*minInplace files fill the per-process file cap inside two
// folders; directories must still be counted past the cap, or the third
// folder is never seen and inplace_modify never fires (the Linux e2e's
// fopen("wb") encryptor ran to completion on a real kernel this way).
func TestInplaceFolderByFolderWalkFires(t *testing.T) {
	for _, root := range []string{"/root/docs", `C:\Users\bob\Documents`} {
		g := New(Options{Push: func(string, string) {}, CanaryDirs: []string{t.TempDir()}})
		sep := "/"
		if root[1] == ':' {
			sep = `\`
		}
		start := time.Now()
		fired := -1
		for i := 0; i < 400 && fired < 0; i++ {
			ev := linsensor.FileEvent{Time: start.Add(time.Duration(i) * 20 * time.Millisecond), PID: 77,
				Image: "/tmp/x/locker", Comm: "locker", Action: "write",
				Path: fmt.Sprintf("%s%sfolder%d%sreport%03d.docx", root, sep, i/100, sep, i)}
			if f := g.det.observe(ev); f != nil && f.kind == "inplace_modify" {
				fired = i
			}
		}
		if fired != 200 {
			t.Errorf("%s: inplace_modify fired at file %d, want 200 (first file of the third folder)", root, fired)
		}
	}
}
