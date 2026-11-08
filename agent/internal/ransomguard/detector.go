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
	// in-place modify: many files that existed before are rewritten across
	// several directories, without renames (encrypt each file over itself).
	minInplace     = 50
	minInplaceDirs = 3

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
	// Windows: installers and servicing, Defender, sync and copy tools,
	// search indexing, build tools. Matched case-insensitively.
	"msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "dism.exe", "dismhost.exe", "cleanmgr.exe",
	"msmpeng.exe", "mpcmdrun.exe", "onedrive.exe", "robocopy.exe", "searchindexer.exe", "git.exe",
	"go.exe", "msbuild.exe", "cl.exe", "link.exe", "devenv.exe",
}

// inplaceSkip are path fragments (lower case, forward slashes) where
// programs rewrite many files in place all day: caches, temp, browser and
// mail profiles, the OS and installed programs. In-place writes there do
// not count; ransomware goes for documents and shares.
var inplaceSkip = []string{
	"/appdata/local/", "/appdata/locallow/", "/temp/", "/tmp/", "/inetcache/",
	"/windows/", "/program files/", "/program files (x86)/", "/programdata/", "/$recycle.bin/",
	"/var/tmp/", "/var/cache/", "/var/log/", "/.cache/", "/proc/", "/sys/", "/dev/", "/run/",
	"/.mozilla/", "/.thunderbird/", "/.config/google-chrome/", "/.config/chromium/",
	"/.config/microsoft-edge/", "/.config/brave", "/snap/",
}

// skipInplace reports whether in-place writes to p are ignored. AppData\Roaming
// holds both settings and caches: its cache-like directories and browser
// and mail profiles are skipped.
func skipInplace(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, s := range inplaceSkip {
		if strings.Contains(l, s) {
			return true
		}
	}
	if i := strings.Index(l, "/appdata/roaming/"); i >= 0 {
		r := l[i:]
		return strings.Contains(r, "cache") || strings.Contains(r, "/mozilla/") || strings.Contains(r, "/thunderbird/")
	}
	return false
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

	created     map[string]bool // files the process created in the window
	inplace     map[string]bool // pre-existing files it wrote
	inplaceDirs map[string]bool
	inTargets   []string // recent in-place writes to sample
	fired       bool
}

type detector struct {
	allow  map[string]bool
	ignore func(string) bool // in-place writes not counted (skipInplace)
	procs  map[uint32]*procWindow
}

func newDetector(allow []string) *detector {
	d := &detector{allow: map[string]bool{}, ignore: skipInplace, procs: map[uint32]*procWindow{}}
	for _, a := range append(append([]string{}, DefaultAllowImages...), allow...) {
		d.allow[strings.ToLower(a)] = true
	}
	return d
}

// finding is a heuristic hit waiting for entropy confirmation.
type finding struct {
	kind    string // extension_change, mass_modify or inplace_modify
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

// dir is p's directory in Linux and Windows path forms alike.
func dir(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i]
	}
	return ""
}

// base is p's file name in Linux and Windows path forms alike.
func base(p string) string { return p[strings.LastIndexAny(p, `/\`)+1:] }

// observe adds one event and returns a finding the first time a process
// crosses a threshold in its window.
func (d *detector) observe(ev linsensor.FileEvent) *finding {
	if d.allow[strings.ToLower(base(ev.Image))] || d.allow[strings.ToLower(ev.Comm)] {
		return nil
	}
	w := d.procs[ev.PID]
	if w == nil || ev.Time.Sub(w.start) >= window {
		if len(d.procs) >= maxTracked {
			d.procs = map[uint32]*procWindow{}
		}
		w = &procWindow{start: ev.Time, image: ev.Image, comm: ev.Comm, ppid: ev.PPID, uid: ev.UID,
			extRenames: map[string]int{}, written: map[string]bool{}, dirs: map[string]bool{},
			created: map[string]bool{}, inplace: map[string]bool{}, inplaceDirs: map[string]bool{}}
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
		if ev.Action == "create" {
			// Windows: a new file (Kernel-File CreateNewFile). Linux: an
			// open with O_CREAT, which may also truncate an existing file;
			// counted as new so unpacking an archive is not "in place".
			if len(w.created) < 4*minWrites {
				w.created[ev.Path] = true
			}
		} else if !w.created[ev.Path] && !w.inplace[ev.Path] && len(w.inplace) < 4*minInplace && !d.ignore(ev.Path) {
			w.inplace[ev.Path] = true
			w.inplaceDirs[dir(ev.Path)] = true
			w.inTargets = appendRecent(w.inTargets, ev.Path)
		}
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
	case len(w.inplace) >= minInplace && len(w.inplaceDirs) >= minInplaceDirs:
		f.kind, f.files, f.targets = "inplace_modify", len(w.inplace), w.inTargets
	default:
		return nil
	}
	w.fired = true
	return f
}

func (w *procWindow) target(p string) { w.targets = appendRecent(w.targets, p) }

// appendRecent keeps the 8 newest paths.
func appendRecent(list []string, p string) []string {
	list = append(list, p)
	if len(list) > 8 {
		list = list[len(list)-8:]
	}
	return list
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

// magic is a file format's header at offset.
type magic struct {
	offset int
	head   string
}

// magics are headers of formats that are high entropy on their own
// (compressed office documents, archives, images, media, executables).
// Encryption replaces the header; a program saving such a file keeps it.
var magics = []magic{
	{0, "PK\x03\x04"}, {0, "PK\x05\x06"}, {0, "PK\x07\x08"}, // docx, xlsx, pptx, odt, zip, jar, apk
	{0, "%PDF"}, {0, "\x89PNG"}, {0, "\xFF\xD8\xFF"}, {0, "GIF8"},
	{0, "\xD0\xCF\x11\xE0"}, // doc, xls, ppt, msi (OLE)
	{0, "{\\rtf"}, {0, "7z\xBC\xAF\x27\x1C"}, {0, "Rar!\x1A\x07"},
	{0, "\x1F\x8B"}, {0, "BZh"}, {0, "\xFD7zXZ\x00"}, {0, "\x28\xB5\x2F\xFD"}, {0, "MSCF"}, // gz, bz2, xz, zstd, cab
	{4, "ftyp"},                                                                // mp4, mov, m4a, heic
	{0, "\x1A\x45\xDF\xA3"}, {0, "RIFF"}, {0, "OggS"}, {0, "fLaC"}, {0, "ID3"}, // mkv/webm, avi/wav/webp, ogg, flac, mp3
	{0, "II*\x00"}, {0, "MM\x00*"}, {0, "8BPS"}, // tiff, psd
	{0, "MZ"}, {0, "\x7FELF"}, {0, "SQLite format 3\x00"},
}

// knownMagic reports whether b starts with a known format header.
func knownMagic(b []byte) bool {
	for _, m := range magics {
		if len(b) >= m.offset+len(m.head) && string(b[m.offset:m.offset+len(m.head)]) == m.head {
			return true
		}
	}
	return false
}

// confirm samples the newest target files: most of them must look
// encrypted, that is high entropy and no known format header (a JPEG or a
// DOCX is high entropy too, but starts with its magic). It returns the mean
// entropy of what it read.
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
		if e >= encryptedEntropy && !knownMagic(buf[:n]) {
			high++
		}
	}
	if read == 0 {
		return false, 0
	}
	return high*2 > read, sum / float64(read)
}
