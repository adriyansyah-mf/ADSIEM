package rollback

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Modes of the group policy (ransomware_rollback).
const (
	ModeOff  = "off"
	ModeAuto = "auto"
)

// DefaultEvery is how often a snapshot is taken.
const DefaultEvery = time.Hour

// firstAfter: the first snapshot after the agent starts or the policy turns on.
const firstAfter = 2 * time.Minute

// reportEvery: a successful snapshot is reported at most this often (errors always).
const reportEvery = 24 * time.Hour

// Controller takes snapshots while the policy is auto and restores after a
// stopped attack.
type Controller struct {
	Store *Store
	Push  func(logType, line string)
	// Mode is the group policy's ransomware_rollback; Paths its
	// rollback_paths (empty: DefaultRoots).
	Mode  func() string
	Paths func() []string
	Every time.Duration

	mu         sync.Mutex
	lastReport time.Time
}

func (c *Controller) on() bool { return c.Mode != nil && c.Mode() == ModeAuto }

func (c *Controller) roots() []string {
	if c.Paths != nil {
		if p := c.Paths(); len(p) > 0 {
			return existing(p)
		}
	}
	return DefaultRoots()
}

// Run snapshots every Every while the policy says auto, until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	every := c.Every
	if every <= 0 {
		every = DefaultEvery
	}
	t := time.NewTimer(firstAfter)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if c.on() {
			c.SnapshotNow()
			t.Reset(every)
		} else {
			t.Reset(firstAfter) // look again soon: the policy may turn it on
		}
	}
}

// SnapshotNow takes one snapshot of the current roots.
func (c *Controller) SnapshotNow() {
	c.mu.Lock()
	c.Store.Roots = c.roots()
	c.mu.Unlock()
	st, err := c.Store.Snapshot()
	c.mu.Lock()
	report := err != nil || time.Since(c.lastReport) >= reportEvery
	if report {
		c.lastReport = time.Now()
	}
	c.mu.Unlock()
	if report && c.Push != nil {
		c.Push(LogType, st.Line(err))
	}
}

// Restore puts back what process pid (image) changed since it first wrote,
// in the folders it wrote in; nothing when the policy is not auto.
func (c *Controller) Restore(pid uint32, image string, since time.Time, dirs []string) {
	if !c.on() {
		return
	}
	res := c.Store.Restore(dirs, since)
	if c.Push != nil {
		c.Push(LogType, res.Line(pid, image, since))
	}
}

func existing(paths []string) []string {
	var out []string
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, filepath.Clean(p))
		}
	}
	return out
}

// DefaultRoots are the folders user data usually lives in, those that exist:
// each user's Documents, Desktop, Pictures and Downloads (Windows: also
// Public Documents; Linux: also /srv and /var/www).
func DefaultRoots() []string {
	var cands []string
	sub := []string{"Documents", "Desktop", "Pictures", "Downloads"}
	if runtime.GOOS == "windows" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		users, _ := filepath.Glob(drive + `\Users\*`)
		for _, u := range users {
			base := strings.ToLower(filepath.Base(u))
			if base == "default" || base == "default user" || base == "all users" {
				continue
			}
			for _, s := range sub {
				cands = append(cands, filepath.Join(u, s))
			}
		}
	} else {
		homes, _ := filepath.Glob("/home/*")
		homes = append(homes, "/root")
		for _, h := range homes {
			for _, s := range sub {
				cands = append(cands, filepath.Join(h, s))
			}
		}
		cands = append(cands, "/srv", "/var/www")
	}
	return existing(cands)
}

// DefaultSkip leaves out caches, version-control internals, editor lock
// files and dependency folders: big, rebuilt, never what a user misses.
func DefaultSkip(path string) bool {
	b := strings.ToLower(path[strings.LastIndexAny(path, `/\`)+1:]) // Linux and Windows forms alike
	switch b {
	case "node_modules", ".git", ".svn", ".hg", ".cache", "__pycache__", ".venv", "venv", "$recycle.bin",
		"thumbs.db", "desktop.ini", ".ds_store":
		return true
	}
	return strings.HasPrefix(b, "~$") || strings.HasPrefix(b, ".~lock.") || strings.HasSuffix(b, ".tmp") ||
		strings.HasSuffix(b, ".adsiem-restore")
}
