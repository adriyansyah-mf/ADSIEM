// Package mountns maps a path as a process sees it to the path the agent
// sees for the same file.
//
// A process in another mount namespace (systemd PrivateTmp, containers) sees
// a different tree: apache's /var/tmp/x is the host's
// /var/tmp/systemd-private-<id>-apache2.service-<id>/tmp/x. Sensors report the
// process's view, so a response (quarantine, stop the program) aimed at that
// path misses the file. Windows has no mount namespaces; this is Linux only.
package mountns

import (
	"bufio"
	"bytes"
	"path"
	"strings"
)

// mount is one /proc/<pid>/mountinfo line: which part (root) of which file
// system (dev) appears at which directory (point).
type mount struct {
	dev   string // major:minor
	root  string // the directory of the file system mounted here
	point string // where it is mounted, as the namespace sees it
}

func parseMountinfo(data []byte) []mount {
	var out []mount
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// id parent major:minor root point options ... - fstype source
		if len(f) < 5 {
			continue
		}
		out = append(out, mount{dev: f[2], root: unescape(f[3]), point: unescape(f[4])})
	}
	return out
}

// unescape decodes mountinfo's octal escapes (\040 space, \011 tab, \012
// newline, \134 backslash).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && isOct(s, i+1) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOct(s string, i int) bool {
	if i+3 > len(s) {
		return false
	}
	for _, c := range []byte(s[i : i+3]) {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}

// within reports whether p is dir or below it.
func within(p, dir string) bool {
	return dir == "/" || p == dir || strings.HasPrefix(p, dir+"/")
}

// rel is p below dir, starting with "/" ("/" for dir itself).
func rel(p, dir string) string {
	if dir == "/" {
		return p
	}
	r := strings.TrimPrefix(p, dir)
	if r == "" {
		return "/"
	}
	return r
}

// translate maps p, a path in the namespace whose mounts are ns, to the same
// file in the namespace whose mounts are host. ok is false when the file
// system part holding p is not mounted in host.
func translate(p string, ns, host []mount) (string, bool) {
	p = path.Clean(p)
	if !path.IsAbs(p) {
		return "", false
	}
	// The mount holding p: the deepest mount point above it; of mounts on the
	// same point, the last one, which hides the others.
	var m *mount
	for i := range ns {
		if within(p, ns[i].point) && (m == nil || len(ns[i].point) >= len(m.point)) {
			m = &ns[i]
		}
	}
	if m == nil {
		return "", false
	}
	inFS := path.Join(m.root, rel(p, m.point))
	// The host mount of the same file system that shows inFS: the one
	// mounting the deepest directory above it; of those, the shallowest
	// mount point.
	var h *mount
	for i := range host {
		c := &host[i]
		if c.dev != m.dev || !within(inFS, c.root) {
			continue
		}
		if h == nil || len(c.root) > len(h.root) || (len(c.root) == len(h.root) && len(c.point) < len(h.point)) {
			h = c
		}
	}
	if h == nil {
		return "", false
	}
	return path.Join(h.point, rel(inFS, h.root)), true
}
