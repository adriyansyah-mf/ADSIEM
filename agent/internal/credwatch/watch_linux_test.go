//go:build linux

package credwatch

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func mkfile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fakeHome(t *testing.T) string {
	h := t.TempDir()
	mkfile(t, filepath.Join(h, ".ssh/id_ed25519"))
	mkfile(t, filepath.Join(h, ".aws/credentials"))
	mkfile(t, filepath.Join(h, ".npmrc"))
	mkfile(t, filepath.Join(h, ".config/google-chrome/Local State"))
	mkfile(t, filepath.Join(h, ".config/google-chrome/Default/Login Data"))
	mkfile(t, filepath.Join(h, ".config/google-chrome/Default/Network/Cookies"))
	mkfile(t, filepath.Join(h, ".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log"))
	mkfile(t, filepath.Join(h, ".config/google-chrome/Default/Local Extension Settings/aapocclcgogkmnckokdopfmhonfmgoek/000003.log"))
	mkfile(t, filepath.Join(h, ".config/google-chrome/Crashpad/settings.dat"))
	mkfile(t, filepath.Join(h, ".mozilla/firefox/ab12.default-release/logins.json"))
	return h
}

func TestTargets(t *testing.T) {
	h := fakeHome(t)
	var got []string
	for _, tg := range Targets(h) {
		rel, _ := filepath.Rel(h, tg.Path)
		if tg.Dir {
			rel += "/"
		}
		got = append(got, rel)
	}
	sort.Strings(got)
	want := []string{".aws/", ".config/google-chrome/", ".config/google-chrome/Default/",
		".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/",
		".config/google-chrome/Default/Network/", ".mozilla/firefox/ab12.default-release/", ".npmrc", ".ssh/"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets\n got %v\nwant %v", got, want)
	}
}

func TestHomes(t *testing.T) {
	h1, h2 := t.TempDir(), t.TempDir()
	passwd := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(passwd, []byte("root:x:0:0:root:"+h1+":/bin/bash\n"+
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"alice:x:1000:1000::"+h2+":/bin/bash\n"+
		"ghost:x:1001:1001::/does/not/exist:/bin/bash\n"+
		"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"), 0o644)
	if got := Homes(passwd); strings.Join(got, ",") != h1+","+h2 {
		t.Fatalf("homes = %v", got)
	}
}

func TestReport(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	w := &Watcher{self: -1, lim: NewLimiter(0), push: func(lt, l string) {
		mu.Lock()
		lines = append(lines, lt+" "+l)
		mu.Unlock()
	}}
	h := fakeHome(t)
	me := int32(os.Getpid())
	w.report(me, filepath.Join(h, ".ssh/id_ed25519"))
	w.report(me, filepath.Join(h, ".ssh/id_ed25519")) // limited
	w.report(me, filepath.Join(h, "project/index.js"))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "credential_access event=credential_access store=ssh_key ") ||
		!strings.Contains(lines[0], "pid=") || !strings.Contains(lines[0], "credwatch.test") {
		t.Fatalf("lines = %q", lines)
	}
}

// TestFanotifyEndToEnd needs root (fanotify): cat opening a marked SSH key
// is reported.
func TestFanotifyEndToEnd(t *testing.T) {
	if os.Getenv("CREDWATCH_E2E") == "" || os.Geteuid() != 0 {
		t.Skip("set CREDWATCH_E2E=1 and run as root (fanotify)")
	}
	h := fakeHome(t)
	got := make(chan string, 8)
	w, err := Start(func(lt, l string) { got <- l })
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	w.homes = func() []string { return []string{h} }
	w.mark()
	if err := exec.Command("cat", filepath.Join(h, ".ssh/id_ed25519")).Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case l := <-got:
		if !strings.Contains(l, "store=ssh_key") || !strings.Contains(l, `/cat"`) {
			t.Fatalf("line = %s", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no line for cat reading the key")
	}
}
