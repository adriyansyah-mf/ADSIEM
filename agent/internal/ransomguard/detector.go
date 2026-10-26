package ransomguard

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
)

// Heuristics over one process's file events in a sliding window.
const (
	window = time.Minute

	// extension change: many renames to a new extension, most to the same one
	// (".locked", ".enc", a random suffix).
	minExtRenames = 20
	sameExtShare  = 0.7
	// mass modify: many files written across many directories while
	// originals are deleted or renamed (encrypt a copy, remove the original).
	minWrites      = 200
	minWriteDirs   = 10
	minDestructive = 50

	entropySample    = 4096
	encryptedEntropy = 7.2 // bits per byte; compressed media and archives come close
	maxTracked       = 4096
)

// DefaultAllowImages are basenames whose bulk file work is normal.
var DefaultAllowImages = []string{
	"dpkg", "apt", "apt-get", "unattended-upgr", "rpm", "dnf", "yum", "zypper", "pacman", "snapd",
	"packagekitd", "flatpak", "git", "rsync", "restic", "borg", "duplicity", "rclone", "updatedb",
	"mandb", "systemd-tmpfiles", "dockerd", "containerd", "docker", "podman", "buildah",
	// Build tools write and rename hundreds of cache files a minute
	// (measured: go build -a). Interpreters are deliberately not here.
	"go", "cargo", "rustc", "cc1", "cc1plus", "ld", "ld.lld", "collect2", "as", "make", "ninja", "cmake",
}

type procWindow struct {
	start     time.Time
	image     string
	comm      string
	ppid, uid uint32

	extRenames map[string]int // new extension -> count
	renames    int
	written    map[string]bool
	dirs       map[string]bool
	destroyed  int
	targets    []string // recent files to sample for entropy
	fired      bool
}

type detector struct {
	allow map[string]bool
	procs map[uint32]*procWindow
}

func newDetector(allow []string) *detector {
	d := &detector{allow: map[string]bool{}, procs: map[uint32]*procWindow{}}
	for _, a := range append(append([]string{}, DefaultAllowImages...), allow...) {
		d.allow[a] = true
	}
	return d
}

// finding is a heuristic hit waiting for entropy confirmation.
type finding struct {
	kind    string // extension_change or mass_modify
	pid     uint32
	ppid    uint32
	uid     uint32
	image   string
	comm    string
	files   int
	ext     string
	targets []string
}

func ext(p string) string { return strings.ToLower(filepath.Ext(p)) }

// observe adds one event and returns a finding the first time a process
// crosses a threshold in its window.
func (d *detector) observe(ev linsensor.FileEvent) *finding {
	if d.allow[filepath.Base(ev.Image)] || d.allow[ev.Comm] {
		return nil
	}
	w := d.procs[ev.PID]
	if w == nil || ev.Time.Sub(w.start) >= window {
		if len(d.procs) >= maxTracked {
			d.procs = map[uint32]*procWindow{}
		}
		w = &procWindow{start: ev.Time, image: ev.Image, comm: ev.Comm, ppid: ev.PPID, uid: ev.UID,
			extRenames: map[string]int{}, written: map[string]bool{}, dirs: map[string]bool{}}
		d.procs[ev.PID] = w
	}
	if w.fired {
		return nil
	}
	switch ev.Action {
	case "rename":
		w.renames++
		w.destroyed++
		if ne := ext(ev.Path); ne != ext(ev.From) && ne != "" {
			w.extRenames[ne]++
		}
		w.target(ev.Path)
	case "create", "write":
		if !w.written[ev.Path] && len(w.written) < 4*minWrites {
			w.written[ev.Path] = true
			w.dirs[filepath.Dir(ev.Path)] = true
		}
		w.target(ev.Path)
	case "delete":
		w.destroyed++
	}

	total, best, bestExt := 0, 0, ""
	for e, n := range w.extRenames {
		total += n
		if n > best {
			best, bestExt = n, e
		}
	}
	f := &finding{pid: ev.PID, ppid: w.ppid, uid: w.uid, image: w.image, comm: w.comm, targets: w.targets}
	switch {
	case total >= minExtRenames && float64(best) >= sameExtShare*float64(total):
		f.kind, f.files, f.ext = "extension_change", total, bestExt
	case len(w.written) >= minWrites && len(w.dirs) >= minWriteDirs && w.destroyed >= minDestructive:
		f.kind, f.files = "mass_modify", len(w.written)
	default:
		return nil
	}
	w.fired = true
	return f
}

func (w *procWindow) target(p string) {
	w.targets = append(w.targets, p)
	if len(w.targets) > 8 {
		w.targets = w.targets[len(w.targets)-8:]
	}
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	e := 0.0
	for _, c := range counts {
		if c > 0 {
			x := float64(c) / float64(len(b))
			e -= x * math.Log2(x)
		}
	}
	return e
}

// confirm samples the newest target files: most of them must look
// encrypted (high entropy). It returns the mean entropy of what it read.
func confirm(targets []string) (bool, float64) {
	read, high := 0, 0
	sum := 0.0
	for i := len(targets) - 1; i >= 0 && read < 3; i-- {
		f, err := os.Open(targets[i])
		if err != nil {
			continue
		}
		buf := make([]byte, entropySample)
		n, _ := f.Read(buf)
		f.Close()
		if n < 512 {
			continue
		}
		e := entropy(buf[:n])
		sum += e
		read++
		if e >= encryptedEntropy {
			high++
		}
	}
	if read == 0 {
		return false, 0
	}
	return high*2 > read, sum / float64(read)
}
