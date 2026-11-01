package ransomguard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Canary files are planted where ransomware looks first (home and data
// directories). Nobody should touch them, so a write, rename or delete is
// a strong signal on its own.
//
// They are hidden so users don't see, open or delete them: dot files on
// Linux (ls and file managers skip them, ransomware walking a directory
// does not), plus the hidden attribute on Windows (hideFile).

// DefaultCanaryNames are the hidden names.
var DefaultCanaryNames = []string{".siem-canary.pdf", ".siem-canary.docx"}

// VisibleCanaryNames are the names used with Options.CanaryVisible (and by
// agents before 1.9): "!" sorts before letters and digits.
var VisibleCanaryNames = []string{"!siem-canary.pdf", ".siem-canary.docx"}

// legacyCanaryNames were planted in plain sight by earlier agents. plant
// removes them, once, when they still hold canary content and are not one
// of the current names.
var legacyCanaryNames = []string{"!siem-canary.pdf"}

// A canary that is changed retireAfter times within retireWindow belongs
// to a directory where something legitimate rewrites or deletes files
// (a deploy, a sync client, a restore). It is not planted there again
// for retireWindow, so that tool is not killed and alerted on forever.
const (
	retireAfter  = 3
	retireWindow = 24 * time.Hour
)

const canaryMarker = "This file is part of the SIEM agent's ransomware protection."

// DefaultCanaryDirs are globs of directories to protect. Web roots are
// left out: deploys rewrite them and a web server would serve the files.
func DefaultCanaryDirs() []string {
	if runtime.GOOS == "windows" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{drive + `\Users\*\Documents`, drive + `\Users\*\Desktop`, drive + `\Users\Public\Documents`}
	}
	return []string{"/root", "/home/*", "/srv"}
}

type canaries struct {
	dirs, names []string
	hide        bool
	now         func() time.Time

	mu      sync.Mutex
	files   map[string]string      // path -> sha256 of what we wrote
	hits    map[string][]time.Time // path -> recent changes, within retireWindow
	retired map[string]time.Time   // path -> when it was retired
	cleaned bool                   // legacy canaries removed
}

func newCanaries(dirs, names []string, visible bool) *canaries {
	if len(dirs) == 0 {
		dirs = DefaultCanaryDirs()
	}
	if len(names) == 0 {
		names = DefaultCanaryNames
		if visible {
			names = VisibleCanaryNames
		}
	}
	return &canaries{dirs: dirs, names: names, hide: !visible, now: time.Now,
		files: map[string]string{}, hits: map[string][]time.Time{}, retired: map[string]time.Time{}}
}

func canaryContent() []byte {
	pad := make([]byte, 2048)
	rand.Read(pad)
	return []byte(fmt.Sprintf(canaryMarker+"\n"+
		"Changing, renaming or deleting it raises an alert. Do not edit.\n%s\n", hex.EncodeToString(pad)))
}

func (c *canaries) expand() []string {
	var dirs []string
	for _, pattern := range c.dirs {
		if strings.ContainsAny(pattern, "*?[") {
			m, _ := filepath.Glob(pattern)
			dirs = append(dirs, m...)
		} else {
			dirs = append(dirs, pattern)
		}
	}
	return dirs
}

// plant writes missing canaries and returns how many exist.
func (c *canaries) plant() int {
	dirs := c.expand()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cleaned {
		c.cleaned = true
		c.removeLegacy(dirs)
	}
	now := c.now()
	for _, d := range dirs {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			continue
		}
		for _, n := range c.names {
			p := filepath.Join(d, n)
			if _, ok := c.files[p]; ok {
				continue
			}
			if at, ok := c.retired[p]; ok {
				if now.Sub(at) < retireWindow {
					continue
				}
				delete(c.retired, p)
			}
			data := canaryContent()
			prepareWrite(p)
			if err := os.WriteFile(p, data, 0o644); err != nil {
				continue
			}
			if c.hide {
				hideFile(p)
			}
			sum := sha256.Sum256(data)
			c.files[p] = hex.EncodeToString(sum[:])
		}
	}
	return len(c.files)
}

// removeLegacy deletes visible canaries left by earlier agents. Only files
// that start with the canary marker go: a user's own file of that name stays.
func (c *canaries) removeLegacy(dirs []string) {
	current := map[string]bool{}
	for _, n := range c.names {
		current[n] = true
	}
	for _, d := range dirs {
		for _, n := range legacyCanaryNames {
			if current[n] {
				continue
			}
			p := filepath.Join(d, n)
			f, err := os.Open(p)
			if err != nil {
				continue
			}
			head := make([]byte, len(canaryMarker))
			_, err = f.Read(head)
			f.Close()
			if err == nil && string(head) == canaryMarker {
				prepareWrite(p)
				os.Remove(p)
			}
		}
	}
}

func (c *canaries) isCanary(path string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.files[path]
	return ok
}

// verify returns the canaries that were changed or removed since they
// were planted, and forgets them so plant writes them again.
func (c *canaries) verify() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var bad []string
	for p, want := range c.files {
		data, err := os.ReadFile(p)
		sum := sha256.Sum256(data)
		if err != nil || hex.EncodeToString(sum[:]) != want {
			bad = append(bad, p)
			delete(c.files, p)
		}
	}
	return bad
}

// strike records a change of a canary (from a file event or verify) and
// drops it so the next plant replaces it. It returns true when this
// change retires the canary: plant leaves that path alone for retireWindow.
func (c *canaries) strike(path string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.files, path)
	now := c.now()
	recent := c.hits[path][:0]
	for _, t := range c.hits[path] {
		if now.Sub(t) < retireWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	if len(recent) < retireAfter {
		c.hits[path] = recent
		return false
	}
	delete(c.hits, path)
	c.retired[path] = now
	return true
}
