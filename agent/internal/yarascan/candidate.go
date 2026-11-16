package yarascan

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Which files the scanner takes from where, and how urgently.
//
// A file in a root (risky directories) is always scanned. A file a sensor
// saw written anywhere else is scanned only when it can run or carry
// something that runs: a program, script, shortcut, macro document or
// container, by name now and by content when it is read. Programs and
// scripts go ahead of everything else in the queue.

var isWindows = runtime.GOOS == "windows"

// runnableExt: programs and scripts, scanned first.
var runnableExt = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true, ".cpl": true, ".ocx": true,
	".msi": true, ".msp": true, ".xll": true, ".drv": true, ".efi": true,
	".ps1": true, ".psm1": true, ".psd1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".wsh": true, ".hta": true, ".bat": true, ".cmd": true, ".lnk": true, ".url": true,
	".sh": true, ".bash": true, ".py": true, ".pl": true, ".rb": true, ".elf": true, ".so": true, ".ko": true,
	".bin": true, ".run": true, ".appimage": true, ".jar": true,
	".php": true, ".phtml": true, ".php5": true, ".php7": true, ".phar": true, ".jsp": true, ".jspx": true,
	".asp": true, ".aspx": true, ".ashx": true, ".asmx": true, ".cfm": true, ".cgi": true,
}

// carrierExt: containers and documents that deliver what runs.
var carrierExt = map[string]bool{
	".zip": true, ".rar": true, ".7z": true, ".gz": true, ".tgz": true, ".tar": true, ".xz": true, ".bz2": true,
	".iso": true, ".img": true, ".vhd": true, ".vhdx": true, ".cab": true,
	".docm": true, ".dotm": true, ".xlsm": true, ".xlsb": true, ".xltm": true, ".pptm": true, ".potm": true,
	".doc": true, ".xls": true, ".ppt": true, ".rtf": true, ".one": true, ".chm": true,
	".html": true, ".htm": true, ".svg": true, ".xhtml": true, ".mht": true,
}

// noiseExt: data files programs rewrite all day; never scanned from a sensor event.
var noiseExt = map[string]bool{
	".log": true, ".journal": true, ".db": true, ".db-wal": true, ".db-shm": true, ".db-journal": true,
	".sqlite": true, ".sqlite3": true, ".sqlite-wal": true, ".sqlite-shm": true, ".wal": true, ".ldb": true,
	".lock": true, ".pid": true, ".sock": true, ".swp": true, ".swo": true, ".etl": true, ".evtx": true,
	".pf": true, ".part": true, ".crdownload": true, ".partial": true, ".download": true, ".opdownload": true,
	".idx": true, ".pack": true, ".jsonl": true, ".ndjson": true, ".csv": true, ".tsv": true,
}

func ext(path string) string { return strings.ToLower(filepath.Ext(path)) }

// slashed: paths compared with forward slashes, folded on Windows.
func slashed(path string) string {
	p := strings.ReplaceAll(path, `\`, "/")
	if isWindows {
		p = strings.ToLower(p)
	}
	return p
}

// pseudoPrefixes hold no files worth scanning (kernel interfaces).
var pseudoPrefixes = []string{"/proc/", "/sys/", "/dev/pts/", "/dev/mqueue/", "/dev/hugepages/"}

// noisyDirs: trees package managers, build tools, browsers and container
// runtimes rewrite in bursts of thousands of files (npm install, pip, apt,
// docker pull, a browser cache). Their files are not taken from the sensors:
// a program there is still scanned when it starts, and a project a
// developer installs is scanned by internal/projscan. Matched on the
// slashed path, folded on Windows.
var noisyDirs = []string{
	"/node_modules/", "/site-packages/", "/dist-packages/", "/__pycache__/", "/.git/", "/go/pkg/mod/",
	"/.cargo/registry/", "/.m2/repository/", "/.gradle/caches/", "/.npm/_cacache/", "/.cache/go-build/",
	"/.cache/pip/", "/.cache/yarn/", "/.cache/google-chrome/", "/.cache/chromium/", "/.cache/mozilla/",
	"/.mozilla/firefox/", "/.config/google-chrome/", "/.config/chromium/",
	"/var/lib/docker/", "/var/lib/containerd/", "/var/lib/containers/", "/var/cache/", "/var/lib/apt/",
	"/var/lib/dpkg/", "/var/lib/rpm/", "/var/lib/snapd/",
	"/appdata/local/google/chrome/user data/", "/appdata/local/microsoft/edge/user data/",
	"/appdata/local/mozilla/firefox/", "/appdata/roaming/mozilla/firefox/", "/appdata/local/packages/",
	"/windows/softwaredistribution/", "/windows/prefetch/", "/windows/winsxs/", "/windows/installer/",
	"/programdata/microsoft/windows defender/", "/$recycle.bin/",
}

// SensorCandidate reports whether a file a sensor saw written may be worth a
// scan, by its name alone (the content is checked when it is read). System
// folders the OS's package manager or updater writes are left to the exec
// checks, as are the noisy trees above.
func SensorCandidate(path string) bool {
	if path == "" {
		return false
	}
	p := slashed(path)
	for _, pre := range pseudoPrefixes {
		if strings.HasPrefix(p, pre) {
			return false
		}
	}
	if strings.HasPrefix(p, "/dev/") && !strings.HasPrefix(p, "/dev/shm/") {
		return false
	}
	if noiseExt[ext(path)] || SystemProgram(path) {
		return false
	}
	lower := strings.ToLower(p)
	for _, d := range noisyDirs {
		if strings.Contains(lower, d) {
			return false
		}
	}
	return true
}

// RunnableName reports a program or script by its extension alone.
func RunnableName(path string) bool { return runnableExt[ext(path)] }

// Runnable reports a program or script by name, or a file with no extension
// (how ELF programs and dropped payloads are usually named): scanned first.
func Runnable(path string) bool {
	e := ext(path)
	if runnableExt[e] {
		return true
	}
	base := filepath.Base(path)
	return e == "" && !strings.HasPrefix(base, ".")
}

// magic: content that runs or carries what runs.
var magic = [][]byte{
	[]byte("MZ"),                        // PE
	[]byte("\x7fELF"),                   // ELF
	[]byte("#!"),                        // script
	[]byte("PK\x03\x04"),                // zip, jar, docx/xlsm, apk
	[]byte("\xd0\xcf\x11\xe0"),          // OLE: doc/xls with macros, msi
	[]byte("{\\rtf"),                    // RTF
	[]byte("Rar!"),                      // RAR
	[]byte("7z\xbc\xaf"),                // 7-Zip
	[]byte("\x1f\x8b"),                  // gzip
	[]byte("L\x00\x00\x00\x01\x14\x02"), // LNK
	[]byte("\xca\xfe\xba\xbe"),          // Java class / Mach-O fat
	[]byte("\xcf\xfa\xed\xfe"),          // Mach-O
	[]byte("<?php"),                     // PHP
	[]byte("MSCF"),                      // CAB
}

// Interesting reports whether a file outside the roots is worth a scan: its
// name says program, script or carrier, or its first bytes do.
func Interesting(path string, head []byte) bool {
	e := ext(path)
	if runnableExt[e] || carrierExt[e] {
		return true
	}
	for _, m := range magic {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// readHead returns up to n bytes from the start of the file at src.
func readHead(src string, n int) []byte {
	f, err := os.Open(src)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	k, _ := io.ReadFull(f, buf)
	return buf[:k]
}

// linuxSystem: directories package managers own. Programs there run all the
// time; scanning each start would cost a read and a hash per exec.
var linuxSystem = []string{
	"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libexec/", "/usr/share/",
	"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/snap/", "/nix/store/",
}

// SystemProgram reports a program in a directory the OS or its package
// manager owns (not checked at start). Temp folders inside them are not.
func SystemProgram(path string) bool {
	p := slashed(path)
	if isWindows {
		root := slashed(os.Getenv("SystemRoot"))
		if root == "" {
			root = "c:/windows"
		}
		if strings.HasPrefix(p, root+"/") {
			return !strings.HasPrefix(p, root+"/temp/")
		}
		for _, pf := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if pf != "" && strings.HasPrefix(p, slashed(pf)+"/") {
				return true
			}
		}
		return false
	}
	for _, pre := range linuxSystem {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// DropperLocation reports a program running from where downloads and
// dropped payloads land (temp, downloads, shared memory, public folders).
// A program there that wrote a file the scanner quarantined is treated as
// the dropper; one installed elsewhere (a browser, an archiver) is not.
func DropperLocation(image string) bool {
	if image == "" {
		return false
	}
	p := slashed(image)
	if isWindows {
		for _, part := range []string{"/appdata/local/temp/", "/windows/temp/", "/downloads/", "/users/public/"} {
			if strings.Contains(p, part) {
				return true
			}
		}
		return false
	}
	for _, pre := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	lower := strings.ToLower(p)
	return (strings.HasPrefix(p, "/home/") || strings.HasPrefix(p, "/root/")) && strings.Contains(lower, "/downloads/")
}
