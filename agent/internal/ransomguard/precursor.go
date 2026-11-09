package ransomguard

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
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
	// CreatorPID is the process that really created this one (Windows: the
	// ETW event header PID); when it differs from PPID the parent was
	// spoofed, and the creator is walked instead. 0: unknown (Linux exec
	// events carry the real parent in PPID).
	CreatorPID uint32
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
	// services: the services each initiator created (sc create), removed
	// on a BYOVD hit; cats: the categories each initiator hit (a downgrade
	// needs a single one).
	services map[string][]svcMark
	cats     map[string]map[string]time.Time
	// jobs feed precursorWorkers responders (a bounded pool); dropped
	// counts the jobs a full queue refused.
	jobs       chan job
	workers    sync.Once
	queueDrops uint64
}

type svcMark struct {
	name string
	at   time.Time
}

// job is one matched start for the responders.
type job struct {
	p       ProcessStart
	h       *hit
	spoofed bool   // the walk starts at the creator, not the claimed parent
	source  string // "amsi" for script content
}

func newPrecursors() *precursors {
	return &precursors{seen: map[uint32]seenProc{}, drops: map[string]drop{},
		scores: map[string][]scoreMark{}, reported: map[string]time.Time{},
		services: map[string][]svcMark{}, cats: map[string]map[string]time.Time{},
		jobs: make(chan job, precursorQueue)}
}

// addServices records services an initiator created.
func (s *precursors) addServices(key string, names []string, now time.Time) {
	if len(names) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.services) >= maxKeys {
		s.services = map[string][]svcMark{}
	}
	var keep []svcMark
	for _, m := range s.services[key] {
		if absDur(now.Sub(m.at)) < dropWindow {
			keep = append(keep, m)
		}
	}
	for _, n := range names {
		keep = append(keep, svcMark{name: n, at: now})
	}
	if len(keep) > 64 {
		keep = keep[len(keep)-64:]
	}
	s.services[key] = keep
}

// servicesOf is what the initiator created within dropWindow.
func (s *precursors) servicesOf(key string, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.services[key] {
		if absDur(now.Sub(m.at)) < dropWindow {
			out = append(out, m.name)
		}
	}
	return out
}

// markCategory records that initiator key hit cat and reports whether it
// hit another category within precursorDedupe.
func (s *precursors) markCategory(key, cat string, now time.Time) (other bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cats) >= maxKeys {
		s.cats = map[string]map[string]time.Time{}
	}
	m := s.cats[key]
	if m == nil {
		m = map[string]time.Time{}
		s.cats[key] = m
	}
	for c, at := range m {
		if c != cat && absDur(now.Sub(at)) < precursorDedupe {
			other = true
		}
	}
	m[cat] = now
	return other
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// remember records a start; p.PPID is the real parent (the creator).
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

// knownTools are the programs the rules match (toolName form).
var knownTools = map[string]bool{"vssadmin": true, "wbadmin": true, "bcdedit": true, "sc": true, "net": true,
	"net1": true, "taskkill": true, "wmic": true, "netsh": true, "reg": true, "powershell": true, "pwsh": true,
	"lvremove": true, "zfs": true, "btrfs": true, "insmod": true, "modprobe": true, "systemctl": true,
	"service": true, "pkill": true, "killall": true, "auditctl": true, "setenforce": true}

// toolOf names the program a process runs: its image, or on Windows, for an
// image that is no known tool outside the system directory (a renamed
// copy), the PE OriginalFilename.
func (g *Guard) toolOf(image, cmdline string) string {
	if image == "" {
		if w := words(normalize(cmdline)); len(w) > 0 {
			return toolName(w[0])
		}
		return ""
	}
	t := toolName(image)
	if g.goos == "windows" && !knownTools[t] && g.origName != nil && !winSystemDir(winPath(image)) {
		if o := g.origName(image); o != "" {
			return toolName(o)
		}
	}
	return t
}

// ObserveProcess takes one process start. It must stay cheap: only the
// command line is matched here; the tree walk and the response run on a
// bounded pool of responders.
func (g *Guard) ObserveProcess(p ProcessStart) {
	if p.Time.IsZero() {
		p.Time = time.Now()
	}
	// A creator equal to the process itself is no creator (unknown).
	spoofed := p.CreatorPID != 0 && p.CreatorPID != p.PID && p.CreatorPID != p.PPID
	if spoofed {
		p.PPID = p.CreatorPID // walk (and remember) the real creator
	}
	g.pre.remember(p)
	if g.rt.Load().Off || p.PID == g.self {
		return
	}
	tool := g.toolOf(p.Image, p.CommandLine)
	var h *hit
	switch g.goos {
	case "windows":
		h = classifyWindows(tool, p.CommandLine)
	case "linux":
		h = classifyLinux(tool, p.CommandLine, func() string {
			if g.cwd == nil {
				return ""
			}
			return g.cwd(p.PID)
		})
	}
	if h == nil {
		return
	}
	g.enqueue(job{p: p, h: h, spoofed: spoofed})
}

// maxScriptLine bounds the script text a line carries.
const maxScriptLine = 512

// ObserveScript takes script content AMSI scanned in process pid (Windows):
// the PowerShell rules see what the script really ran, whatever the launch
// command line looked like.
func (g *Guard) ObserveScript(pid uint32, image string, content []byte) {
	if g.rt.Load().Off || pid == g.self || g.goos != "windows" {
		return
	}
	h := classifyScript(string(content))
	if h == nil || h.category == "" {
		return
	}
	text := strings.ToValidUTF8(string(content), "?")
	if len(text) > maxScriptLine {
		text = text[:maxScriptLine]
	}
	p := ProcessStart{PID: pid, Image: image, CommandLine: text, Time: time.Now()}
	if c, ok := g.pre.lookup(pid); ok {
		p.PPID = c.ppid
		if p.Image == "" {
			p.Image = c.image
		}
	}
	g.enqueue(job{p: p, h: h, source: "amsi"})
}

const (
	precursorQueue   = 256
	precursorWorkers = 4
)

// enqueue hands a job to the responders (inline when not async). A full
// queue drops the job and counts it: never an unbounded goroutine per event.
func (g *Guard) enqueue(j job) {
	if !g.async {
		g.precursor(j)
		return
	}
	g.pre.workers.Do(func() {
		for i := 0; i < precursorWorkers; i++ {
			go func() {
				for j := range g.pre.jobs {
					g.precursor(j)
				}
			}()
		}
	})
	select {
	case g.pre.jobs <- j:
	default:
		n := atomic.AddUint64(&g.pre.queueDrops, 1)
		slog.Warn("ransomguard: precursor queue full, start dropped", "pid", j.p.PID, "image", j.p.Image, "dropped", n)
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

func (g *Guard) precursor(j job) {
	p, h := j.p, j.h
	rt := g.rt.Load()
	ini, walked, alive, protected := g.initiator(p)
	if g.ownCommand(p, walked) {
		return // started by the agent itself (live response, its own reverts)
	}
	key := fmt.Sprintf("%d|%s", ini.pid, strings.ToLower(ini.image))
	g.pre.addServices(key, h.services, p.Time)
	if h.category == "" {
		return // a plain service created: kept for a BYOVD hit's cleanup
	}
	d := detection{kind: "precursor", confirmed: true, precursor: h.category, cmdline: p.CommandLine,
		preImage: p.Image, prePID: p.PID, pid: ini.pid, ppid: ini.ppid, image: ini.image, comm: base(ini.image),
		iniProtected: protected, parentSpoofed: j.spoofed, source: j.source}
	dropped := h.inDrivers && g.droppedByTree(h.driver, ini, p.Time)
	if h.inDrivers && !g.userWritable(ini.image) && !dropped {
		// A kernel service on a driver in System32\drivers the initiator did
		// not bring: not acted on, never silent (unconfirmed: no alert).
		d.confirmed = false
		if g.pre.firstQuiet(key+"|byovd", p.Time) {
			g.report(d)
		}
		return
	}
	if !g.pre.count(key, h, p.Time) {
		return
	}
	other := g.pre.markCategory(key, h.category, p.Time)
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
	if !j.spoofed && !other {
		if d.downgraded = g.downgrade(h, ini, walked); d.downgraded != "" {
			// Routine tooling: reported (a lower alert), not stopped.
			if g.pre.firstQuiet(key, p.Time) {
				g.report(d)
			}
			return
		}
	}
	target, image := ini.pid, ini.image
	if protected || !alive {
		target, image = p.PID, p.Image
	}
	if g.respond(&d, target, image) {
		if len(h.revert) > 0 {
			g.revert(&d, h)
		}
		if h.category == catBYOVD {
			g.removeDriver(&d, h, key, !h.inDrivers || dropped, p.Time)
		}
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
var winWritable = []string{"/temp/", "/systemtemp/", "/tasks/", "/tracing/", "/debug/", "/registration/crmlog/",
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
		if ancestors[pid] && !ok {
			// the agent (or its service host), even when the table cannot
			// read it: protected, never walked past
			q, live = proc{pid: pid}, true
			return q, append(walked, q), live, true
		}
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
	return strings.HasPrefix(l, sysRoot+"/temp/") || strings.HasPrefix(l, sysRoot+"/systemtemp/")
}

// droppedByTree: driver was written within dropWindow by the initiator's
// tree (the initiator, any process under it such as a cmd /c copy, the same
// program) or from a user-writable place.
func (g *Guard) droppedByTree(driver string, ini proc, now time.Time) bool {
	d, ok := g.pre.dropOf(driver, now)
	if !ok {
		return false
	}
	return d.pid == ini.pid || sameImage(d.image, ini.image) || g.userWritable(d.image) ||
		g.userWritable(d.from) || g.descends(d.pid, ini.pid)
}

// descends reports whether pid is under ancestor (start cache, then the
// live table).
func (g *Guard) descends(pid, ancestor uint32) bool {
	var look procLookup
	if g.live != nil {
		look = g.live()
	}
	for i := 0; i < maxWalk && pid != 0; i++ {
		q, ok, _ := g.find(pid, look)
		if !ok || q.ppid == pid {
			return false
		}
		if q.ppid == ancestor {
			return true
		}
		pid = q.ppid
	}
	return false
}

// ownCommand: the precursor, or a process walked up to its initiator, is
// one the agent started (ownproc), checked against the start cache so a
// reused PID does not borrow it. On Linux a direct child of the agent also
// counts: an exec's parent cannot be spoofed there, and the exec event can
// beat the registration of the PID.
func (g *Guard) ownCommand(p ProcessStart, walked []proc) bool {
	if g.goos == "linux" && p.PPID == g.self {
		return true
	}
	if g.own == nil {
		return false
	}
	mine := func(pid uint32) bool {
		if !g.own(pid) {
			return false
		}
		c, ok := g.pre.lookup(pid)
		return !ok || c.ppid == g.self
	}
	if mine(p.PID) {
		return true
	}
	for _, q := range walked {
		if mine(q.pid) || g.goos == "linux" && q.ppid == g.self {
			return true
		}
	}
	return false
}

// rotationTools rotate snapshots routinely (by base name; "pve" prefix:
// the Proxmox schedulers).
var rotationTools = map[string]bool{"zfs-auto-snapshot": true, "sanoid": true, "syncoid": true, "vzdump": true,
	"snapper": true, "timeshift": true, "pyznap": true, "zrepl": true, "pve-zsync": true}

func rotationTool(name string) bool { return rotationTools[name] || strings.HasPrefix(name, "pve") }

// interpreters run a script named as their first operand.
func interpreter(name string) bool {
	switch name {
	case "sh", "bash", "dash", "perl", "ruby":
		return true
	}
	return strings.HasPrefix(name, "python")
}

// downgrade says why a hit is only reported: snapshot rotation by known
// tooling or on a schedule from a root-owned system program, or a security
// product stopped by an installed program. Critical shadow, backup, boot
// and driver precursors are never downgraded.
func (g *Guard) downgrade(h *hit, ini proc, walked []proc) string {
	switch h.category {
	case catSnapshot:
		for _, q := range walked {
			b := base(q.image)
			if rotationTool(b) && g.trustedLocation(q.image) {
				return "rotation_tool"
			}
			if interpreter(b) && g.trustedLocation(q.image) {
				if s := firstOperand(q.cmdline); strings.HasPrefix(s, "/") && rotationTool(base(s)) && g.trustedLocation(s) {
					return "rotation_tool"
				}
			}
		}
		if g.scheduled(ini) {
			return "scheduled"
		}
	case catDefense:
		if g.trustedLocation(ini.image) {
			return "trusted_initiator"
		}
	}
	return ""
}

// firstOperand is a command line's first word after the program that is
// not a switch (the script an interpreter runs).
func firstOperand(cmdline string) string {
	f := strings.Fields(cmdline)
	for _, a := range f[min(1, len(f)):] {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

var schedulers = map[string]bool{"cron": true, "crond": true, "anacron": true, "atd": true, "systemd": true}

// scheduled: a root-owned system program started by cron, at or systemd
// (a timer's service), or one of them.
func (g *Guard) scheduled(ini proc) bool {
	if g.goos != "linux" || !g.trustedLocation(ini.image) {
		return false
	}
	if schedulers[base(ini.image)] || ini.ppid == 1 {
		return true
	}
	var look procLookup
	if g.live != nil {
		look = g.live()
	}
	parent, ok, _ := g.find(ini.ppid, look)
	return ok && schedulers[base(parent.image)] && g.trustedLocation(parent.image)
}

// removeDriver undoes a BYOVD install: the driver's service and every
// service the initiator created in dropWindow are stopped and deleted, and
// the driver file is removed when it is the initiator's (outside the driver
// directories, or dropped there by its tree).
func (g *Guard) removeDriver(d *detection, h *hit, key string, removeFile bool, now time.Time) {
	var names []string
	seen := map[string]bool{}
	for _, n := range append([]string{h.svc}, g.pre.servicesOf(key, now)...) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	var done []string
	if g.runCmd != nil {
		for _, n := range names {
			g.runCmd("sc", "stop", n) // not running: fine
			out, err := g.runCmd("sc", "delete", n)
			if err != nil && !strings.Contains(string(out), "1060") { // 1060: no such service
				d.err = strings.TrimSpace(d.err + " revert service:" + n + ": " + err.Error())
				continue
			}
			done = append(done, "service:"+n)
		}
	}
	if len(done) > 0 {
		d.reverted = strings.TrimPrefix(d.reverted+","+strings.Join(done, ","), ",")
	}
	if removeFile && h.driver != "" && g.removeFile != nil {
		if err := g.removeFile(h.driver); err != nil && !os.IsNotExist(err) {
			d.err = strings.TrimSpace(d.err + " remove " + h.driver + ": " + err.Error())
		} else {
			d.removed = h.driver
		}
	}
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
		out, err := g.runCmd("bcdedit", args...)
		if err != nil && !strings.Contains(strings.ToLower(string(out)), "not found") { // not set: already the default
			d.err = strings.TrimSpace(d.err + " revert " + h.reverted[i] + ": " + err.Error())
			continue
		}
		done = append(done, h.reverted[i])
	}
	d.reverted = strings.Join(done, ",")
}
