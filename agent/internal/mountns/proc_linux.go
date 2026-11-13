//go:build linux

package mountns

import (
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cacheTTL = 30 * time.Second
	cacheMax = 256
)

type cached struct {
	mounts []mount
	at     time.Time
}

const procRoot = "/proc"

var (
	mu    sync.Mutex
	cache = map[string]cached{}
)

// nsOf is the mount namespace of pid ("mnt:[4026531841]"), "" if unknown.
func nsOf(pid string) string {
	ns, _ := os.Readlink(procRoot + "/" + pid + "/ns/mnt")
	return ns
}

// mountsOf returns pid's mounts, cached per namespace: every process of a
// namespace shares them.
func mountsOf(ns, pid string) []mount {
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[ns]; ok && time.Since(c.at) < cacheTTL {
		return c.mounts
	}
	data, err := os.ReadFile(procRoot + "/" + pid + "/mountinfo")
	if err != nil {
		return nil
	}
	if len(cache) >= cacheMax {
		cache = map[string]cached{}
	}
	m := parseMountinfo(data)
	cache[ns] = cached{mounts: m, at: time.Now()}
	return m
}

// HostPath is p, a path as process pid sees it, as the agent sees it. It
// returns "" when pid shares the agent's mount namespace, is gone, or p maps
// to the same path (nothing to add).
func HostPath(pid int, p string) string {
	if pid <= 0 || !path.IsAbs(p) {
		return ""
	}
	return hostPath(strconv.Itoa(pid), p, selfNS())
}

var (
	selfOnce sync.Once
	self     string
)

// selfNS is the agent's own mount namespace; it does not change.
func selfNS() string {
	selfOnce.Do(func() { self = nsOf("self") })
	return self
}

func hostPath(pid, p, self string) string {
	ns := nsOf(pid)
	if ns == "" || self == "" || ns == self {
		return ""
	}
	out, ok := translate(p, mountsOf(ns, pid), mountsOf(self, "self"))
	if !ok || out == path.Clean(p) {
		return ""
	}
	return out
}

// Candidate is an existing file that a path reported by a process in another
// mount namespace can mean.
type Candidate struct {
	Path string
	// Running: a process of that namespace runs p, so this is the file it
	// executes.
	Running bool
}

// Locate finds what p, a path that does not exist for the agent, names in
// the mount namespaces of the processes on the host: each distinct existing
// file once, with Running set if any process runs p.
func Locate(p string) []Candidate {
	p = path.Clean(p)
	if !path.IsAbs(p) {
		return nil
	}
	self := selfNS()
	entries, err := os.ReadDir(procRoot)
	if err != nil || self == "" {
		return nil
	}
	tried := map[string]bool{}
	index := map[string]int{}
	var out []Candidate
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		ns := nsOf(pid)
		if ns == "" || ns == self {
			continue
		}
		exe, _ := os.Readlink(procRoot + "/" + pid + "/exe")
		running := strings.TrimSuffix(exe, " (deleted)") == p
		if tried[ns] && !running {
			continue
		}
		tried[ns] = true
		host := hostPath(pid, p, self)
		if host == "" {
			continue
		}
		if _, err := os.Lstat(host); err != nil {
			continue
		}
		if i, ok := index[host]; ok {
			out[i].Running = out[i].Running || running
			continue
		}
		index[host] = len(out)
		out = append(out, Candidate{Path: host, Running: running})
	}
	return out
}
