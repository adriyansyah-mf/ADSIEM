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

// In-place modification only counts where user data lives: a game or an
// updater rewriting its own .pak/.bin files is not ransomware.
func TestInplaceOnlyInUserData(t *testing.T) {
	quiet := []string{
		`C:\Program Files\Game\data`, `C:\Program Files (x86)\Steam\steamapps`, `C:\Users\bob\AppData\Roaming\Game`,
		`C:\Users\bob\AppData\Local\Game`, `C:\ProgramData\Vendor`, `C:\Windows\SoftwareDistribution`,
		`C:\Games\Game\data`, `D:\Program Files\Game`,
		"/usr/share/game", "/var/lib/postgresql/16/main", "/var/cache/x", "/tmp/x", "/opt/app/data", "/etc/x",
	}
	fires := []string{
		`C:\Users\bob\Documents`, `C:\Users\Public\Documents`, `D:\Projects`, `E:\Share\Finance`, `\\fs01\share\dept`,
		"/home/alice/docs", "/root/work", "/srv/share", "/var/www/html", "/mnt/nas", "/media/usb", "/data/files", "/opt/data/files",
	}
	for _, root := range quiet {
		sep := "/"
		if strings.Contains(root, `\`) {
			sep = `\`
		}
		if f := writes(newDetector(nil), 40, root, sep, 3*minInplace, 4); f != nil {
			t.Errorf("%s: fired %+v", root, f)
		}
	}
	for _, root := range fires {
		sep := "/"
		if strings.Contains(root, `\`) {
			sep = `\`
		}
		if f := writes(newDetector(nil), 41, root, sep, minInplace, minInplaceDirs); f == nil || f.kind != "inplace_modify" {
			t.Errorf("%s: no inplace_modify (%+v)", root, f)
		}
	}
}

// In place, high entropy without a header is not enough (game assets,
// compressed blobs): most samples must have lost the header their extension
// promises, or the process must also have given files a new uniform extension.
func TestInplaceConfirmNeedsHeaderGone(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, header []byte) string {
		p := filepath.Join(dir, name)
		writeSample(t, p, header)
		return p
	}
	encrypted := []string{mk("a.docx", nil), mk("b.pdf", nil), mk("c.jpg", nil)}
	assets := []string{mk("d.pak", nil), mk("e.bin", nil), mk("f.dat", nil)}
	text := []string{mk("g.txt", nil), mk("h.csv", nil), mk("i.txt", nil)}
	legit := []string{mk("j.docx", headers[".docx"]), mk("k.pdf", headers[".pdf"]), mk("l.jpg", headers[".jpg"])}
	half := []string{mk("m.pak", nil), mk("n.docx", nil)}
	for name, c := range map[string]struct {
		files []string
		want  bool
	}{
		"encrypted docx/pdf/jpg": {encrypted, true},
		"random .pak/.bin/.dat":  {assets, false},
		"random .txt/.csv":       {text, false},
		"legit, headers kept":    {legit, false},
		"half lost a header":     {half, true},
	} {
		if ok, _ := confirmInplace(c.files); ok != c.want {
			t.Errorf("%s: confirmed %t, want %t", name, ok, c.want)
		}
	}
}

func TestInplaceUniformExtension(t *testing.T) {
	d := newDetector(nil)
	for i := 0; i < 6; i++ {
		p := fmt.Sprintf("/home/alice/docs/old%d.txt", i)
		d.observe(ev(42, "rename", p+".lck", p, 0))
	}
	f := writes(d, 42, "/home/alice/docs", "/", minInplace, minInplaceDirs)
	if f == nil || f.kind != "inplace_modify" || !f.uniformExt {
		t.Fatalf("finding = %+v", f)
	}
	if f := writes(newDetector(nil), 43, "/home/alice/docs", "/", minInplace, minInplaceDirs); f == nil || f.uniformExt {
		t.Fatalf("no renames: uniformExt set: %+v", f)
	}
}

// A game updater rewriting 60 asset files with high-entropy data: even
// where it counts (a user folder), it is reported, not stopped.
func TestGuardInplaceGameAssetsNotKilled(t *testing.T) {
	g, out, killed := inplaceGuard(t)
	dir := t.TempDir()
	for i := 0; i < 60; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("pack%d", i%3))
		os.MkdirAll(sub, 0o755)
		p := filepath.Join(sub, fmt.Sprintf("chunk%02d%s", i, []string{".pak", ".bin"}[i%2]))
		writeSample(t, p, nil)
		g.Observe(linsensor.FileEvent{Time: t0.Add(time.Duration(i) * time.Millisecond), Action: "write", Path: p, PID: 68,
			Image: `D:\Games\Game\updater.exe`, Comm: "updater.exe"})
	}
	if l := out.wait(t, 1)[0]; !strings.HasPrefix(l, "detection=inplace_modify confirmed=false response=none") || len(*killed) != 0 {
		t.Fatalf("line = %s killed=%v", l, *killed)
	}
}
