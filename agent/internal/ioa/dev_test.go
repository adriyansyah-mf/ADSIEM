package ioa

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// credLine: a credential_access line as internal/credwatch formats it.
func credLine(pid, ppid int, image, store, target string) (string, string) {
	return "credential_access", fmt.Sprintf(`event=credential_access store=%s target=%s image=%s pid=%d ppid=%d user="1000"`,
		store, linKV(target), linKV(image), pid, ppid)
}

func linNetPort(pid int, comm, dst string, port int) (string, string) {
	lt, l := linNet(pid, comm, dst)
	return lt, strings.Replace(l, "dport=4444", fmt.Sprintf("dport=%d", port), 1)
}

func has(rules []string, id string) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}

// The shape of a fake recruiter's "coding test" on Linux: npm start runs the
// project, its code drops a hidden Python stage in ~/.n2 and runs it; the
// stage reads the browser's saved passwords and calls home on port 1224.
func TestDevCompromiseLinux(t *testing.T) {
	h := newHarness(t, "linux")
	h.feed(linExec(1000, 1, "/usr/bin/node", "node server.js", "/usr/bin/npm", 1000))
	h.feed(linFile(1000, 1, "/usr/bin/node", "/home/dev/.n2/pay"))
	h.wait(time.Second)
	h.feed(linExec(1001, 1000, "/usr/bin/python3", "python3 /home/dev/.n2/pay", "/usr/bin/node", 1000))
	h.feed(credLine(1001, 1000, "/usr/bin/python3.12", "browser_passwords", "/home/dev/.config/google-chrome/Default/Login Data"))
	h.feed(linNetPort(1001, "python3", "203.0.113.50", 1224))
	got := h.rules()
	for _, want := range []string{"ioa_dev_project_dropper", "ioa_dev_credential_read", "ioa_dev_odd_port"} {
		if !has(got, want) {
			t.Fatalf("%s missing: %v", want, got)
		}
	}
	for _, l := range h.lines {
		if f := fields(l); f["rule"] == "ioa_dev_credential_read" && !strings.Contains(f["chain"], "Login Data (browser_passwords)") {
			t.Fatalf("chain = %q", f["chain"])
		}
	}
}

func TestDevCompromiseWindows(t *testing.T) {
	h := newHarness(t, "windows")
	node := `C:\Program Files\nodejs\node.exe`
	stage := `C:\Users\alice\.npl\x.js`
	h.feed(winProc(500, 400, node, `node index.js`, `C:\Windows\System32\cmd.exe`))
	h.feed(winFile(500, node, stage))
	h.feed(winProc(501, 500, node, `"C:\Program Files\nodejs\node.exe" "`+stage+`"`, node))
	if !has(h.rules(), "ioa_dev_project_dropper") {
		t.Fatalf("rules = %v", h.rules())
	}
}

func TestDevCompromiseBenign(t *testing.T) {
	h := newHarness(t, "linux")
	// a build: npm run build writes dist/, node runs it
	h.feed(linExec(1, 0, "/usr/bin/node", "node build.js", "/usr/bin/npm", 1000))
	h.feed(linFile(1, 0, "/usr/bin/node", "/home/dev/app/dist/main.js"))
	h.feed(linExec(2, 1, "/usr/bin/node", "node /home/dev/app/dist/main.js", "/usr/bin/node", 1000))
	// pip building an sdist: setup.py in its temp folder
	h.feed(linExec(10, 0, "/usr/bin/pip3", "pip3 install foo", "/bin/bash", 1000))
	h.feed(linFile(10, 0, "/usr/bin/pip3", "/tmp/pip-install-abc/foo/setup.py"))
	h.feed(linExec(11, 10, "/usr/bin/python3", "python3 /tmp/pip-install-abc/foo/setup.py egg_info", "/usr/bin/pip3", 1000))
	// a cache under ~/.cache
	h.feed(linExec(20, 0, "/usr/bin/node", "node x", "/bin/bash", 1000))
	h.feed(linFile(20, 0, "/usr/bin/node", "/home/dev/.cache/tool/run.sh"))
	h.feed(linExec(21, 20, "/bin/sh", "sh /home/dev/.cache/tool/run.sh", "/usr/bin/node", 1000))
	// the API on 443, the database on 5432
	h.feed(linNetPort(1, "node", "203.0.113.8", 443))
	h.feed(linNetPort(1, "node", "203.0.113.9", 5432))
	// ssh reading its own key never reaches IOA (credwatch drops it); a
	// credential read by a process outside any interpreter tree: no chain
	h.feed(linExec(30, 0, "/usr/bin/gnome-keyring-daemon", "gnome-keyring-daemon", "/lib/systemd/systemd", 1000))
	h.feed(credLine(30, 0, "/usr/bin/gnome-keyring-daemon", "ssh_key", "/home/dev/.ssh/id_ed25519"))
	if len(h.lines) != 0 {
		t.Fatalf("benign: %v", h.rules())
	}
}

func TestArgPaths(t *testing.T) {
	got := argPaths(`"C:\Program Files\nodejs\node.exe" "C:\Users\a b\.npl\x.js" --config=/home/u/.n2/c.json -v plain`)
	want := []string{`C:\Program Files\nodejs\node.exe`, `C:\Users\a b\.npl\x.js`, `/home/u/.n2/c.json`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("argPaths = %q", got)
	}
}

func TestHiddenHome(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/dev/.n2/pay": true, `C:\Users\alice\.npl\x.js`: true, "/root/.x/y": true,
		"/home/dev/.cache/x": false, "/home/dev/.config/app/x": false, "/home/dev/.bashrc": false,
		"/home/dev/app/x": false, "/opt/.x/y": false, `C:\Users\alice\AppData\x`: false,
	} {
		if hiddenHome(p) != want {
			t.Errorf("hiddenHome(%s) != %v", p, want)
		}
	}
}
