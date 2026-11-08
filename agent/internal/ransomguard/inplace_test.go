package ransomguard

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// writes sends n in-place writes of pre-existing files spread over dirs
// directories under root (Linux or Windows path form) and returns the
// finding, if any.
func writes(d *detector, pid uint32, root, sep string, n, dirs int) *finding {
	var f *finding
	for i := 0; i < n; i++ {
		p := root + sep + fmt.Sprintf("dir%d", i%dirs) + sep + fmt.Sprintf("report%03d.docx", i)
		if got := d.observe(ev(pid, "write", p, "", time.Duration(i)*100*time.Millisecond)); got != nil {
			f = got
		}
	}
	return f
}

func TestInplaceModifyFires(t *testing.T) {
	for _, c := range []struct{ name, root, sep string }{
		{"linux", "/home/alice/Documents", "/"},
		{"windows", `C:\Users\bob\Documents`, `\`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := writes(newDetector(nil), 20, c.root, c.sep, minInplace, minInplaceDirs)
			if f == nil || f.kind != "inplace_modify" || f.files != minInplace || f.pid != 20 {
				t.Fatalf("finding = %+v", f)
			}
			if len(f.targets) == 0 || !strings.HasPrefix(f.targets[len(f.targets)-1], c.root) {
				t.Fatalf("targets = %v", f.targets)
			}
			if f := writes(newDetector(nil), 21, c.root, c.sep, minInplace-1, minInplaceDirs); f != nil {
				t.Fatalf("%d files fired: %+v", minInplace-1, f)
			}
			if f := writes(newDetector(nil), 22, c.root, c.sep, 3*minInplace, minInplaceDirs-1); f != nil {
				t.Fatalf("%d directories fired: %+v", minInplaceDirs-1, f)
			}
		})
	}
}

func TestInplaceModifyIgnoresSelfCreatedFiles(t *testing.T) {
	d := newDetector(nil)
	for i := 0; i < 3*minInplace; i++ {
		p := fmt.Sprintf("/home/alice/out/d%d/new%03d.bin", i%5, i)
		if f := d.observe(ev(30, "create", p, "", 0)); f != nil {
			t.Fatalf("create fired: %+v", f)
		}
		if f := d.observe(ev(30, "write", p, "", 0)); f != nil {
			t.Fatalf("writes to files the process created fired: %+v", f)
		}
	}
}

func TestInplaceModifyIgnoresCacheAndTemp(t *testing.T) {
	for _, root := range []string{
		`C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default`,
		`C:\Users\bob\AppData\LocalLow\Sun`,
		`C:\Users\bob\AppData\Roaming\Code\Cache`,
		`C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default`,
		`C:\Windows\Temp`,
		`C:\Windows\System32`,
		`C:\ProgramData\App`,
		`C:\Program Files\App`,
		"/tmp/build",
		"/var/tmp/x",
		"/home/alice/.cache/pip",
		"/home/alice/.mozilla/firefox/x.default",
		"/home/alice/.config/google-chrome/Default",
		"/var/cache/apt",
	} {
		sep := "/"
		if strings.Contains(root, `\`) {
			sep = `\`
		}
		if f := writes(newDetector(nil), 31, root, sep, 3*minInplace, 5); f != nil {
			t.Errorf("%s: fired %+v", root, f)
		}
	}
}

func TestInplaceModifyAllowlist(t *testing.T) {
	d := newDetector([]string{"photoeditor.exe"})
	for _, img := range []string{`C:\Program Files\Microsoft OneDrive\OneDrive.exe`, `C:\Tools\PhotoEditor.exe`, "/usr/bin/rsync"} {
		for i := 0; i < 2*minInplace; i++ {
			e := ev(32, "write", fmt.Sprintf(`C:\Users\bob\Pictures\d%d\p%d.jpg`, i%4, i), "", 0)
			e.Image, e.Comm = img, filepath.Base(img)
			if f := d.observe(e); f != nil {
				t.Fatalf("%s is allowed: %+v", img, f)
			}
		}
	}
}

// Magic headers of formats that are high entropy on their own.
var headers = map[string][]byte{
	".docx": []byte("PK\x03\x04"),
	".pdf":  []byte("%PDF-1.7\n"),
	".jpg":  {0xFF, 0xD8, 0xFF, 0xE0},
	".png":  []byte("\x89PNG\r\n\x1a\n"),
	".xls":  {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
	".mp4":  []byte("\x00\x00\x00\x20ftypisom"),
}

func writeSample(t *testing.T, path string, header []byte) {
	t.Helper()
	data := make([]byte, 8192)
	rand.Read(data)
	copy(data, header)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Encrypted office files, PDFs and photos lose their header; the same
// formats saved legitimately keep it and are high entropy too.
func TestConfirmNeedsMagicGone(t *testing.T) {
	dir := t.TempDir()
	for ext, magic := range headers {
		var enc, legit []string
		for i := 0; i < 3; i++ {
			e := filepath.Join(dir, fmt.Sprintf("enc%d%s", i, ext))
			writeSample(t, e, nil)
			enc = append(enc, e)
			l := filepath.Join(dir, fmt.Sprintf("legit%d%s", i, ext))
			writeSample(t, l, magic)
			legit = append(legit, l)
		}
		if ok, e := confirm(enc); !ok {
			t.Errorf("%s: encrypted (no header) not confirmed, entropy %.2f", ext, e)
		}
		if ok, e := confirm(legit); ok {
			t.Errorf("%s: a legit high-entropy file with its header confirmed, entropy %.2f", ext, e)
		}
	}
	// No known magic (txt, csv): high entropy alone confirms.
	var txt []string
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("notes%d.txt", i))
		writeSample(t, p, nil)
		txt = append(txt, p)
	}
	if ok, _ := confirm(txt); !ok {
		t.Error("encrypted .txt not confirmed")
	}
}

func inplaceGuard(t *testing.T) (*Guard, *sink, *[]uint32) {
	t.Helper()
	var out sink
	killed := &[]uint32{}
	g := New(Options{Push: out.push, CanaryDirs: []string{filepath.Join(t.TempDir(), "none")}, Kill: true})
	g.det.ignore = func(string) bool { return false } // the samples live under the temp dir
	g.response = func(pid uint32) (int, error) { *killed = append(*killed, pid); return 1, nil }
	return g, &out, killed
}

func TestGuardInplaceEncryptionKills(t *testing.T) {
	g, out, killed := inplaceGuard(t)
	dir := t.TempDir()
	for i := 0; i < minInplace; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("d%d", i%minInplaceDirs))
		os.MkdirAll(sub, 0o755)
		p := filepath.Join(sub, fmt.Sprintf("f%02d%s", i, []string{".docx", ".pdf", ".jpg"}[i%3]))
		writeSample(t, p, nil) // encrypted in place: random bytes, header gone
		g.Observe(linsensor.FileEvent{Time: t0, Action: "write", Path: p, PID: 66, Image: `C:\Users\bob\Downloads\invoice.exe`, Comm: "invoice.exe"})
	}
	l := out.wait(t, 1)[0]
	if !strings.HasPrefix(l, fmt.Sprintf("detection=inplace_modify confirmed=true response=killed Files=%d", minInplace)) ||
		len(*killed) != 1 || (*killed)[0] != 66 {
		t.Fatalf("line = %s killed=%v", l, *killed)
	}
}

// A photo editor saving 60 JPEGs (or Office saving documents) writes high-
// entropy files in place that keep their header: reported, not stopped.
func TestGuardInplaceLegitHighEntropyOnlyReports(t *testing.T) {
	g, out, killed := inplaceGuard(t)
	dir := t.TempDir()
	for i := 0; i < 60; i++ {
		sub := filepath.Join(dir, fmt.Sprintf("album%d", i%4))
		os.MkdirAll(sub, 0o755)
		p := filepath.Join(sub, fmt.Sprintf("IMG_%04d.jpg", i))
		writeSample(t, p, headers[".jpg"])
		g.Observe(linsensor.FileEvent{Time: t0, Action: "write", Path: p, PID: 67, Image: `C:\Program Files\Editor\editor.exe`, Comm: "editor.exe"})
	}
	l := out.wait(t, 1)[0]
	if !strings.HasPrefix(l, "detection=inplace_modify confirmed=false response=none") || len(*killed) != 0 {
		t.Fatalf("line = %s killed=%v", l, *killed)
	}
}
