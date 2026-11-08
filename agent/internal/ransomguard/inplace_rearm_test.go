package ransomguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// I5: a Documents tree mixes header-less files (txt, csv, md) with Office
// files. The newest writes being .txt must not hide the encrypted .docx:
// files whose extension promises a header are sampled first.
func TestInplaceSamplesHeaderPromisingFiles(t *testing.T) {
	g, out, killed := inplaceGuard(t)
	dir := t.TempDir()
	for i := 0; i < minInplace; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", i%3))
		os.MkdirAll(sub, 0o755)
		ext := ".docx"
		if i%4 != 0 || i >= minInplace-4 { // mostly text, and the newest four
			ext = []string{".txt", ".csv", ".md"}[i%3]
		}
		p := filepath.Join(sub, fmt.Sprintf("f%02d%s", i, ext))
		writeSample(t, p, nil)
		g.Observe(linsensor.FileEvent{Time: t0.Add(time.Duration(i) * time.Millisecond), Action: "write", Path: p, PID: 80,
			Image: "/tmp/.x/locker", Comm: "locker"})
	}
	if l := out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=inplace_modify confirmed=true response=killed") || len(*killed) != 1 {
		t.Fatalf("line = %s killed %v", l, *killed)
	}
}

// I5: an unconfirmed in-place hit does not mute the process for the rest of
// its window: it is evaluated again every further minInplace files, and an
// earlier unconfirmed mass_modify/extension_change does not hide it.
func TestInplaceReArmsAfterUnconfirmedHit(t *testing.T) {
	d := newDetector(nil)
	at := time.Duration(0)
	fires := 0
	for i := 0; i < 4*minInplace; i++ {
		at += time.Millisecond
		if f := d.observe(ev(81, "write", fmt.Sprintf("/home/a/docs/d%d/f%03d.docx", i%3, i), "", at)); f != nil {
			if f.kind != "inplace_modify" || f.files != (fires+1)*minInplace {
				t.Fatalf("fire %d: %+v", fires, f)
			}
			fires++
		}
	}
	if fires != 4 {
		t.Fatalf("%d in-place evaluations in one window, want 4", fires)
	}

	d2 := newDetector(nil)
	for i := 0; i < minExtRenames; i++ { // an unconfirmed-looking extension_change first
		if f := d2.observe(ev(82, "rename", fmt.Sprintf("/home/a/x%d.bak", i), fmt.Sprintf("/home/a/x%d.txt", i), at)); f != nil && f.kind != "extension_change" {
			t.Fatalf("%+v", f)
		}
	}
	if f := writes(d2, 82, "/home/a/docs", "/", minInplace, minInplaceDirs); f == nil || f.kind != "inplace_modify" {
		t.Fatalf("in-place not evaluated after another heuristic fired: %+v", f)
	}
}
