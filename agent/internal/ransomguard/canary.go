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
)

// Canary files are planted where ransomware looks first (home and data
// directories) under names that sort early. Nobody should touch them, so
// a write, rename or delete is a strong signal on its own.

// DefaultCanaryNames: "!" sorts before letters and digits, the dot file
// catches tools that walk hidden files too.
var DefaultCanaryNames = []string{"!siem-canary.pdf", ".siem-canary.docx"}

// DefaultCanaryDirs are globs of directories to protect.
func DefaultCanaryDirs() []string {
	if runtime.GOOS == "windows" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{drive + `\Users\*\Documents`, drive + `\Users\*\Desktop`, drive + `\Users\Public\Documents`}
	}
	return []string{"/root", "/home/*", "/srv", "/var/www"}
}

type canaries struct {
	dirs, names []string

	mu    sync.Mutex
	files map[string]string // path -> sha256 of what we wrote
}

func newCanaries(dirs, names []string) *canaries {
	if len(dirs) == 0 {
		dirs = DefaultCanaryDirs()
	}
	if len(names) == 0 {
		names = DefaultCanaryNames
	}
	return &canaries{dirs: dirs, names: names, files: map[string]string{}}
}

func canaryContent() []byte {
	pad := make([]byte, 2048)
	rand.Read(pad)
	return []byte(fmt.Sprintf("This file is part of the SIEM agent's ransomware protection.\n"+
		"Changing, renaming or deleting it raises an alert. Do not edit.\n%s\n", hex.EncodeToString(pad)))
}

// plant writes missing canaries and returns how many exist.
func (c *canaries) plant() int {
	var dirs []string
	for _, pattern := range c.dirs {
		if strings.ContainsAny(pattern, "*?[") {
			m, _ := filepath.Glob(pattern)
			dirs = append(dirs, m...)
		} else {
			dirs = append(dirs, pattern)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range dirs {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			continue
		}
		for _, n := range c.names {
			p := filepath.Join(d, n)
			if _, ok := c.files[p]; ok {
				continue
			}
			data := canaryContent()
			if err := os.WriteFile(p, data, 0o644); err != nil {
				continue
			}
			sum := sha256.Sum256(data)
			c.files[p] = hex.EncodeToString(sum[:])
		}
	}
	return len(c.files)
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

// forget drops a canary that was reported through a file event so the
// next plant replaces it.
func (c *canaries) forget(path string) {
	c.mu.Lock()
	delete(c.files, path)
	c.mu.Unlock()
}
