package ransomguard

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Precursors: ransomware deletes shadow copies and backups, turns boot
// recovery off, loads a vulnerable driver and stops security products
// before it encrypts (IronChain did all of it in 6 s). The guard sees every
// process start (ObserveProcess), matches its command line
// (precursor_rules.go) and, in stop mode, kills the program behind it, the
// initiator, with its whole tree.
//
// The initiator is found by walking up from the precursor past shells and
// LOLBins (cmd, powershell, sc, net, sh, sudo...) to the first other
// ancestor. Shells are walked past and processes protected only by their
// full path (a cmd.exe or services.exe outside the system directory is
// neither). A protected initiator (services.exe, explorer, sshd, cron, a
// package manager, the agent's own ancestors) is never killed: the
// precursor process alone is.

const (
	scoreNeeded     = 3
	scoreWindow     = time.Minute
	precursorDedupe = 10 * time.Minute
	// dropWindow is how long a .sys file written to disk counts as
	// "just dropped" for a kernel service created on it.
	dropWindow = 10 * time.Minute
	maxSeen    = 8192
	maxDrops   = 256
	maxKeys    = 1024
	maxWalk    = 32
)

// ProcessStart is one process start: Windows ETW, Linux exec (eBPF).
type ProcessStart struct {
	PID, PPID   uint32
	Image       string // full path
	CommandLine string
	Time        time.Time
}

// proc is a process in the tree walk; cmdline is known only for a start
// the feed delivered.
type proc struct {
	pid, ppid uint32
	image     string
	cmdline   string
}

// procLookup reports a live process's parent and image; nil where there is
// no process table.
type procLookup func(pid uint32) (proc, bool)

type seenProc struct {
	proc
	at time.Time
}

type drop struct {
	pid         uint32
	image, from string
	at          time.Time
}

type scoreMark struct {
	key string
	at  time.Time
}

// precursors is the guard's precursor state.
type precursors struct {
	mu sync.Mutex
	// seen: process starts from the feed, so a parent that already exited
	// (or whose PID was reused) is still known by what it was.
	seen     map[uint32]seenProc
	drops    map[string]drop // .sys files written, by driverPath
	scores   map[string][]scoreMark
	reported map[string]time.Time
}

func newPrecursors() *precursors {
	return &precursors{seen: map[uint32]seenProc{}, drops: map[string]drop{},
		scores: map[string][]scoreMark{}, reported: map[string]time.Time{}}
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (s *precursors) remember(p ProcessStart) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) >= maxSeen {
		for pid, e := range s.seen {
			if absDur(p.Time.Sub(e.at)) > precursorDedupe {
				delete(s.seen, pid)
			}
		}
		if len(s.seen) >= maxSeen {
			s.seen = map[uint32]seenProc{}
		}
	}
	s.seen[p.PID] = seenProc{proc: proc{pid: p.PID, ppid: p.PPID, image: p.Image, cmdline: p.CommandLine}, at: p.Time}
}

func (s *precursors) lookup(pid uint32) (proc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.seen[pid]
	return e.proc, ok
}

func (s *precursors) dropped(path string, d drop) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.drops) >= maxDrops {
		s.drops = map[string]drop{}
	}
	s.drops[path] = d
}

func (s *precursors) dropOf(path string, now time.Time) (drop, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.drops[path]
	return d, ok && absDur(now.Sub(d.at)) < dropWindow
}

// count records hit h for initiator key and reports whether to act on it:
// a critical hit, or enough score indicators.
func (s *precursors) count(key string, h *hit, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.score != nil {
		var marks []scoreMark
		for _, m := range s.scores[key] {
			if absDur(now.Sub(m.at)) < scoreWindow {
				marks = append(marks, m)
			}
		}
	next:
		for _, k := range h.score {
			for i := range marks {
				if marks[i].key == k {
					marks[i].at = now
					continue next
				}
			}
			marks = append(marks, scoreMark{key: k, at: now})
		}
		if len(s.scores) >= maxKeys {
			s.scores = map[string][]scoreMark{}
		}
		s.scores[key] = marks
		if len(marks) < scoreNeeded {
			return false
		}
	}
	return true
}

// firstQuiet reports whether a line where nothing was done (report_only,
// excluded) is the first for initiator key in precursorDedupe. Lines of
// kills are never held back.
func (s *precursors) firstQuiet(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.reported[key]; ok && absDur(now.Sub(last)) < precursorDedupe {
		return false
	}
	if len(s.reported) >= maxKeys {
		s.reported = map[string]time.Time{}
	}
	s.reported[key] = now
	return true
}

// ObserveProcess takes one process start. It must stay cheap: only the
// command line is matched here; the tree walk and the response run on
// their own goroutine.
func (g *Guard) ObserveProcess(p ProcessStart) {
	if p.Time.IsZero() {
		p.Time = time.Now()
	}
	g.pre.remember(p)
	if g.rt.Load().Off || p.PID == g.self || p.PPID == g.self {
		return // the agent's own commands (a bcdedit revert, live response)
	}
	cmdline := p.CommandLine
	if cmdline == "" {
		cmdline = p.Image
	}
	var h *hit
	switch g.goos {
	case "windows":
		h = classifyWindows(cmdline)
	case "linux":
		h = classifyLinux(cmdline, func() string {
			if g.cwd == nil {
				return ""
			}
			return g.cwd(p.PID)
		})
	}
	if h == nil {
		return
	}
	if g.async {
		go g.precursor(p, h)
	} else {
		g.precursor(p, h)
	}
}

// observeDrop records a .sys file written to disk (BYOVD drops the driver
// right before it creates the kernel service).
func (g *Guard) observeDrop(pid uint32, image, action, p, from string, at time.Time) {
	if g.goos != "windows" || (action != "create" && action != "write" && action != "rename") ||
		!strings.HasSuffix(strings.ToLower(p), ".sys") {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	g.pre.dropped(driverPath(p), drop{pid: pid, image: image, from: from, at: at})
}

func (g *Guard) precursor(p ProcessStart, h *hit) {
	rt := g.rt.Load()
	ini, walked, alive, protected := g.initiator(p)
	if h.inDrivers && !g.userWritable(ini.image) && !g.droppedBy(h.driver, ini, p.Time) {
		return // a kernel service on a driver the initiator did not bring
	}
	key := fmt.Sprintf("%d|%s", ini.pid, strings.ToLower(ini.image))
	if !g.pre.count(key, h, p.Time) {
		return
	}
	d := detection{kind: "precursor", confirmed: true, precursor: h.category, cmdline: p.CommandLine,
		preImage: p.Image, prePID: p.PID, pid: ini.pid, ppid: ini.ppid, image: ini.image, comm: base(ini.image),
		iniProtected: protected}
	excluded, ignored := g.excluded(rt, p, ini, walked)
	d.exclIgnored = ignored
	if excluded {
		// An admin task the policy allows: reported (no alert), not stopped.
		d.response = "excluded"
		if g.pre.firstQuiet(key, p.Time) {
			g.report(d)
		}
		return
	}
	target, image := ini.pid, ini.image
	if protected || !alive {
		target, image = p.PID, p.Image
	}
	if g.respond(&d, target, image) && len(h.revert) > 0 {
		g.revert(&d, h)
	}
	// Every kill is reported; a line where nothing was done (report_only)
	// once per initiator in precursorDedupe.
	if d.response != "none" || g.pre.firstQuiet(key, p.Time) {
		g.report(d)
	}
}

// excluded matches the precursor and every process walked up to the
// initiator (the shells running an admin's script included) against the
// policy's ransomware exclusions. An image exclusion (a full path, never a
// bare program name) excludes. A command-line exclusion excludes only when
// the initiator runs from a location a standard user cannot write: anyone
// can put an excluded string in a command line, ransomware included;
// otherwise ignored says why ("untrusted_initiator").
func (g *Guard) excluded(rt *Runtime, p ProcessStart, ini proc, walked []proc) (bool, string) {
	image := func(img string) bool { return img != "" && rt.ExcludedImage != nil && rt.ExcludedImage(img) }
	cmd := func(c string) bool { return c != "" && rt.ExcludedCommandLine != nil && rt.ExcludedCommandLine(c) }
	if image(p.Image) {
		return true, ""
	}
	cmdHit := cmd(p.CommandLine)
	for _, q := range walked {
		if image(q.image) {
			return true, ""
		}
		cmdHit = cmdHit || cmd(q.cmdline)
	}
	if !cmdHit {
		return false, ""
	}
	if g.trustedLocation(ini.image) {
		return true, ""
	}
	return false, "untrusted_initiator"
}

// programDirs are the Windows program directories (lower case, forward
// slashes, trailing slash).
var programDirs = func() []string {
	out := []string{systemDrive + "/program files/", systemDrive + "/program files (x86)/"}
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if d := os.Getenv(v); d != "" {
			out = append(out, strings.TrimSuffix(winPath(d), "/")+"/")
		}
	}
	return out
}()

// winWritable are directories under the Windows directory that standard
// users can write.
var winWritable = []string{"/temp/", "/tasks/", "/tracing/", "/debug/", "/registration/crmlog/",
	"/system32/tasks/", "/system32/spool/", "/system32/com/dmp/", "/system32/fxstmp/",
	"/syswow64/tasks/", "/syswow64/com/dmp/", "/syswow64/fxstmp/", "/servicing/sessions/"}

// trustedLocation: the image is installed where a standard user cannot
// write. Windows: under the Windows directory (not its user-writable
// folders) or a Program Files directory, as a full long path (an 8.3 or
// unresolved \Device\ path is not trusted). Linux: under /usr, /bin, /sbin,
// /lib*, /opt or /etc, and owned by root.
func (g *Guard) trustedLocation(image string) bool {
	switch g.goos {
	case "windows":
		l := winPath(image)
		if !winDrivePath(l) || strings.Contains(l, "/../") || strings.Contains(l, "/./") || strings.Contains(l, "~") {
			return false
		}
		if rest, ok := strings.CutPrefix(l, sysRoot+"/"); ok {
			for _, w := range winWritable {
				if strings.HasPrefix("/"+rest, w) {
					return false
				}
			}
			return true
		}
		for _, d := range programDirs {
			if strings.HasPrefix(l, d) {
				return true
			}
		}
		return false
	case "linux":
		if image == "" || image != path.Clean(image) || !strings.HasPrefix(image, "/") {
			return false
		}
		for _, d := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/opt/", "/etc/"} {
			if strings.HasPrefix(image, d) {
				return g.rootOwned == nil || g.rootOwned(image)
			}
		}
	}
	return false
}

// initiator walks up from p's parent past shells and LOLBins. It returns
// the first other ancestor, the processes walked (the initiator included),
// whether the initiator is still the one seen (not exited, its PID not
// reused), and whether it is protected. A walk that ends at a process gone
// gives the topmost shell; no ancestor at all, the precursor itself.
func (g *Guard) initiator(p ProcessStart) (ini proc, walked []proc, alive, protected bool) {
	var look procLookup
	if g.live != nil {
		look = g.live()
	}
	ancestors := g.selfAncestors(look)
	var top proc
	topAlive, haveTop := false, false
	pid := p.PPID
	for i := 0; i < maxWalk && pid != 0; i++ {
		q, ok, live := g.find(pid, look)
		if !ok {
			break
		}
		walked = append(walked, q)
		if ancestors[q.pid] || g.protectedProc(q) {
			return q, walked, live, true
		}
		if !g.passThrough(q.image) {
			return q, walked, live, false
		}
		top, topAlive, haveTop = q, live, true
		if q.ppid == pid {
			break
		}
		pid = q.ppid
	}
	if haveTop {
		return top, walked, topAlive, false
	}
	return proc{pid: p.PID, ppid: p.PPID, image: p.Image, cmdline: p.CommandLine}, walked, true, false
}

// find looks pid up in the feed's starts and the live process table. A
// PID seen starting as one program and now running another was reused:
// the one seen is returned, not alive.
func (g *Guard) find(pid uint32, look procLookup) (proc, bool, bool) {
	c, inSeen := g.pre.lookup(pid)
	var l proc
	live := false
	if look != nil {
		l, live = look(pid)
	}
	switch {
	case live && inSeen && l.image != "" && !sameImage(c.image, l.image):
		return c, true, false
	case live:
		if inSeen {
			l.cmdline = c.cmdline // the live table has no command line
			if l.image == "" {
				l.image = c.image
			}
		}
		return l, true, true
	case inSeen:
		return c, true, false
	}
	return proc{}, false, false
}

// sameImage compares two image paths; a bare or relative name (a start
// whose full path was not known yet) is compared by its base name.
func sameImage(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	full := func(s string) bool {
		return strings.HasPrefix(s, "/") || len(s) > 2 && s[1] == ':' || strings.HasPrefix(s, `\\`)
	}
	if !full(a) || !full(b) {
		return strings.EqualFold(base(a), base(b))
	}
	return false
}

// selfAncestors is the agent and its ancestors (never killed).
func (g *Guard) selfAncestors(look procLookup) map[uint32]bool {
	out := map[uint32]bool{g.self: true}
	if look == nil {
		return out
	}
	for pid, i := g.self, 0; i < maxWalk; i++ {
		q, ok := look(pid)
		if !ok || q.ppid == 0 || q.ppid == pid {
			break
		}
		out[q.ppid] = true
		pid = q.ppid
	}
	return out
}

// sysRoot is the Windows directory, lower case with forward slashes.
var sysRoot = func() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return winPath(r)
	}
	return systemDrive + "/windows"
}()

// winPath is a Windows path in lower case with forward slashes, without
// the \\?\ or \??\ prefix.
func winPath(p string) string {
	l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	l = strings.TrimPrefix(l, "//?/")
	return strings.TrimPrefix(l, "/??/")
}

func winDrivePath(l string) bool { return len(l) >= 3 && l[1] == ':' && l[2] == '/' }

// winSystemDir: under the Windows system directories only administrators
// and TrustedInstaller can write.
func winSystemDir(l string) bool {
	if strings.Contains(l, "/../") || strings.Contains(l, "/./") {
		return false
	}
	for _, d := range []string{"/system32/", "/syswow64/", "/winsxs/", "/servicing/"} {
		if strings.HasPrefix(l, sysRoot+d) {
			return true
		}
	}
	return false
}

// criticalNames never die, when they run from the system directory:
// terminating them crashes or locks up Windows (the same list as the
// kill_process task, internal/task/response_windows.go). The same name
// anywhere else is not the real thing and may be killed.
var criticalNames = map[string]bool{
	"smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "lsass.exe": true, "lsaiso.exe": true, "svchost.exe": true,
	"fontdrvhost.exe": true, "dwm.exe": true, "lsm.exe": true, "memcompression": true,
	"registry": true, "secure system": true,
}

// winProtectedNames are never killed as initiators when they run from the
// system directory (explorer.exe from the Windows directory).
var winProtectedNames = map[string]bool{
	"explorer.exe": true, "userinit.exe": true, "wmiprvse.exe": true, "taskhostw.exe": true, "taskeng.exe": true,
	"mmc.exe": true, "msiexec.exe": true, "trustedinstaller.exe": true, "tiworker.exe": true, "sshd.exe": true,
	"sihost.exe": true, "windowsterminal.exe": true, "openconsole.exe": true,
}

var winPassNames = map[string]bool{
	"cmd.exe": true, "conhost.exe": true, "powershell.exe": true, "pwsh.exe": true, "wscript.exe": true,
	"cscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "wmic.exe": true, "sc.exe": true,
	"net.exe": true, "net1.exe": true,
}

// linProtectedNames: session hosts, schedulers, package managers and the
// agent (from a system directory).
var linProtectedNames = map[string]bool{
	"systemd": true, "init": true, "sshd": true, "sshd-session": true, "login": true, "agetty": true,
	"cron": true, "crond": true, "atd": true, "anacron": true, "tmux": true, "screen": true,
	"gnome-terminal-server": true, "konsole": true, "xterm": true, "xfce4-terminal": true, "mate-terminal": true,
	"tilix": true, "kitty": true, "alacritty": true, "gnome-shell": true, "plasmashell": true,
	"containerd-shim": true, "containerd-shim-runc-v2": true, "runc": true, "containerd": true, "dockerd": true,
	"dpkg": true, "rpm": true, "apt": true, "apt-get": true, "yum": true, "dnf": true, "zypper": true,
	"packagekitd": true, "siem-agent": true,
}

var linPassNames = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "fish": true, "busybox": true,
	"env": true, "xargs": true, "nohup": true, "timeout": true, "setsid": true, "sudo": true, "su": true,
	"doas": true, "nice": true, "ionice": true, "flock": true, "stdbuf": true,
}

func linSystemDir(p string) bool {
	if p != path.Clean(p) {
		return false
	}
	for _, d := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// protectedProc: never the kill target. A process whose image cannot be
// told (System, a kernel thread, a path not resolved) counts as protected.
func (g *Guard) protectedProc(q proc) bool {
	switch g.goos {
	case "windows":
		l := winPath(q.image)
		if q.pid <= 4 || !winDrivePath(l) {
			return true
		}
		b := base(l)
		if criticalNames[b] || winProtectedNames[b] {
			if winSystemDir(l) || l == sysRoot+"/"+b {
				return true
			}
			if (b == "windowsterminal.exe" || b == "openconsole.exe") &&
				strings.HasPrefix(l, systemDrive+"/program files/windowsapps/microsoft.windowsterminal") {
				return true
			}
		}
		return false
	default:
		if q.pid <= 1 || q.image == "" {
			return true
		}
		return linProtectedNames[base(q.image)] && linSystemDir(q.image)
	}
}

func (g *Guard) passThrough(image string) bool {
	switch g.goos {
	case "windows":
		l := winPath(image)
		return winPassNames[base(l)] && (winSystemDir(l) || strings.HasPrefix(l, systemDrive+"/program files/powershell/"))
	default:
		return linPassNames[base(image)] && linSystemDir(image)
	}
}

// userWritable: a Windows image a standard user could have put there.
func (g *Guard) userWritable(image string) bool {
	if g.goos != "windows" || image == "" {
		return false
	}
	l := winPath(image)
	if strings.HasPrefix(l, "//") {
		return true // a share
	}
	if !winDrivePath(l) {
		return false
	}
	if l[:2] != systemDrive {
		return true // a data disk or a USB stick
	}
	for _, d := range []string{"/users/", "/programdata/", "/perflogs/", "/$recycle.bin/"} {
		if strings.HasPrefix(l[2:], d) {
			return true
		}
	}
	return strings.HasPrefix(l, sysRoot+"/temp/")
}

// droppedBy: driver was written within dropWindow by the initiator (same
// PID or program) or from a user-writable place.
func (g *Guard) droppedBy(driver string, ini proc, now time.Time) bool {
	d, ok := g.pre.dropOf(driver, now)
	if !ok {
		return false
	}
	return d.pid == ini.pid || sameImage(d.image, ini.image) || g.userWritable(d.image) || g.userWritable(d.from)
}

// revert undoes a boot configuration change with bcdedit.
func (g *Guard) revert(d *detection, h *hit) {
	if g.runCmd == nil {
		return
	}
	if g.revertDelay > 0 {
		time.Sleep(g.revertDelay) // a bcdedit not killed in time has finished
	}
	var done []string
	for i, args := range h.revert {
		if err := g.runCmd("bcdedit", args...); err != nil {
			d.err = strings.TrimSpace(d.err + " revert " + h.reverted[i] + ": " + err.Error())
			continue
		}
		done = append(done, h.reverted[i])
	}
	d.reverted = strings.Join(done, ",")
}
