package ransomguard

import (
	"os"
	"strings"
	"sync"
	"time"
)

// Trust: nothing in the guard is trusted by its file name. A sync client
// (syncClients) is trusted only from where a user cannot put a binary
// (Program Files, admin-only), or from the per-user install under
// %LOCALAPPDATA%\Microsoft\OneDrive, which the user can write, only when it
// carries a valid Authenticode signature by Microsoft Corporation.

// syncClients may rewrite, rename or delete a canary: OneDrive's Known
// Folder Move syncs Documents and Desktop, canaries included, between a
// user's devices.
var syncClients = []string{"onedrive.exe", "onedrive.sync.service.exe", "filecoauth.exe"}

// syncClientDirs are OneDrive's admin-only install locations under the
// system drive (lower case, forward slashes).
var syncClientDirs = []string{"/program files/microsoft onedrive/", "/program files (x86)/microsoft onedrive/"}

// userSyncClientDir is the per-user install, under Users\<user>.
const userSyncClientDir = "/appdata/local/microsoft/onedrive/"

func syncName(image string) bool {
	b := base(image)
	for _, n := range syncClients {
		if strings.EqualFold(b, n) {
			return true
		}
	}
	return false
}

// trustedSync reports whether image is a sync client to trust (see above);
// signed checks the Microsoft signature of a per-user install.
func trustedSync(image string, signed func(string) bool) bool {
	if !syncName(image) { // cheap: most images stop here, without allocating
		return false
	}
	l := strings.ToLower(strings.ReplaceAll(image, `\`, "/"))
	if strings.Contains(l, "/../") || strings.Contains(l, "/./") || len(l) < 3 || l[:2] != systemDrive || l[2] != '/' {
		return false
	}
	rest := l[2:]
	for _, d := range syncClientDirs {
		if strings.HasPrefix(rest, d) {
			return true
		}
	}
	if u, ok := strings.CutPrefix(rest, "/users/"); ok {
		if i := strings.IndexByte(u, '/'); i > 0 && strings.HasPrefix(u[i:], userSyncClientDir) {
			return signed != nil && signed(image)
		}
	}
	return false
}

// signCache remembers signature verdicts per path, size and modification
// time: a binary replaced in place is checked again. Bounded.
type signCache struct {
	verify func(string) bool
	mu     sync.Mutex
	m      map[string]signEntry
}

type signEntry struct {
	size  int64
	mtime time.Time
	ok    bool
}

const maxSignCache = 256

func newSignCache(verify func(string) bool) *signCache {
	return &signCache{verify: verify, m: map[string]signEntry{}}
}

func (c *signCache) signed(p string) bool {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	c.mu.Lock()
	e, ok := c.m[p]
	c.mu.Unlock()
	if ok && e.size == info.Size() && e.mtime.Equal(info.ModTime()) {
		return e.ok
	}
	v := c.verify(p)
	c.mu.Lock()
	if len(c.m) >= maxSignCache {
		c.m = map[string]signEntry{}
	}
	c.m[p] = signEntry{size: info.Size(), mtime: info.ModTime(), ok: v}
	c.mu.Unlock()
	return v
}

// microsoftSigned is the platform check, cached; false off Windows.
var microsoftSigned = newSignCache(verifyMicrosoft).signed

// setSigned replaces the signature check (tests).
func (g *Guard) setSigned(f func(string) bool) { g.signed.Store(&f) }

// trusted reports whether image is a trusted sync client.
func (g *Guard) trusted(image string) bool {
	return trustedSync(image, *g.signed.Load())
}
