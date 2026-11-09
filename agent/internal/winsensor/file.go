package winsensor

import (
	"strconv"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

// Log types for file and image telemetry (Sigma windows / file_event,
// file_delete, image_load, driver_load).
const (
	LogTypeFile  = "windows_etw_file"
	LogTypeImage = "windows_etw_image"
)

// Event groups that etw.disabled_events can switch off.
const (
	GroupFile  = "file"
	GroupImage = "image"
)

const kernelFileProvider = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}" // Microsoft-Windows-Kernel-File

// Microsoft-Windows-Kernel-File events, as measured on the Windows runner
// (etw.TestFileAndImageSources). The event header's PID is the process that
// did it.
const (
	// fileCreate is every open (FileName, FileObject). Only remembered: a
	// rename names the new path alone, the old one is the open of the same
	// FileObject. Its FileName may hold 8.3 components (RUNNER~1).
	fileCreate = 12
	// fileDeletePath: FilePath of a deleted file.
	fileDeletePath = 26
	// fileRenamePath: FilePath is the new name.
	fileRenamePath = 27
	// fileCreateNew: FileName of a file that did not exist (Sysmon 11).
	fileCreateNew = 30
)

// Keywords: FILENAME, CREATE, DELETE_PATH, RENAME_SETLINK_PATH, CREATE_NEW_FILE.
// Reads and closes never reach the agent; writes only when the guard listens.
const kernelFileKeywords = 0x10 | 0x80 | 0x400 | 0x800 | 0x1000

var fileEventIDs = []uint16{fileCreate, fileDeletePath, fileRenamePath, fileCreateNew}

// Kernel-File Write (KERNEL_FILE_KEYWORD_WRITE): ByteOffset, Irp, FileObject,
// FileKey, IssuingThreadId, IOSize, IOFlags, ExtraFlags, and no name. The
// header PID is the writer; the name comes from the open (fileCreate) of the
// same FileObject. Writes only feed the anti-ransomware guard (an in-place
// encryptor neither renames nor deletes): they are never SIEM lines, and
// they come through a session of their own (writeProvider) so that their
// volume never costs the SIEM's file events anything.
const (
	fileWrite    = 16
	writeKeyword = 0x200
	// maxWrites bounds the (pid, file) set that makes a file written in
	// many chunks one event per fileWindow.
	maxWrites = 16384
)

// writeProvider is the guard's own Kernel-File session: opens (decoded, for
// their FileObject and name) and writes, fast-decoded (etw.Fast): the
// header PID and FileObject, read at its fixed offset after ByteOffset
// (8 bytes) and Irp (a pointer). Only for the event versions whose layout
// that is (writeVersions; others are decoded with TDH), and checked against
// TDH on the first writeVerify writes: a mismatch switches the session to
// TDH for good, and shows in windows_etw_status (FastMismatches,
// FastDecodeOff).
func writeProvider() (etw.Provider, []etw.Fast) {
	return etw.Provider{GUID: kernelFileProvider, Keywords: 0x10 | 0x80 | writeKeyword,
			EventIDs: []uint16{fileCreate, fileWrite}},
		[]etw.Fast{{ID: fileWrite, Offset: func(ptr int) int { return 8 + ptr }, Versions: writeVersions,
			Field: "FileObject", Verify: writeVerify}}
}

// Kernel-File Write versions with ByteOffset, Irp, FileObject first (the
// manifest's Write template; v1 adds a trailing ExtraFlags).
var writeVersions = []uint8{0, 1}

// writeVerify is how many writes the fast decode is checked against TDH at
// session start.
const writeVerify = 64

// writeKey is a process and the device path it writes.
type writeKey struct {
	pid  uint32
	name string
}

// Microsoft-Windows-Kernel-Process ImageLoad (WINEVENT_KEYWORD_IMAGE): ProcessID,
// ImageName (an NT device path). A load into PID 0 or 4 is a kernel driver.
const (
	imageLoadEvent    = 5
	imageKeyword      = 0x40
	fileDirectoryOp   = 0x1    // FILE_DIRECTORY_FILE in CreateOptions
	fileDeleteOnClose = 0x1000 // FILE_DELETE_ON_CLOSE in CreateOptions
)

const (
	// fileBudget is how many file lines one process may ship per
	// fileWindow; the rest are counted into one summary line (as linsensor).
	fileBudget = 30
	fileWindow = time.Minute
	// maxObjects bounds the FileObject -> name map kept for renames.
	maxObjects = 16384
	// imageDedupe: a process image loading the same DLL is reported once a
	// day, so the steady state is the loads not seen before.
	imageDedupe   = 24 * time.Hour
	maxImagePairs = 50000
	maxFileProcs  = 8192
)

// fileSummaryEvent is the EventID of a summary line: no Sysmon ID, so it
// reaches no Sigma category, only search.
const fileSummaryEvent = 1100

// skipFilePrefixes (lower case, after the drive letter) are written all day
// by Windows itself.
var skipFilePrefixes = []string{`\windows\prefetch\`, `\system volume information\`, `\$extend\`}

// Options configure StartWith.
type Options struct {
	// Disabled event groups (GroupFile, GroupImage).
	Disabled []string
	// OnFile, if set, sees every file event before rate limiting.
	OnFile func(FileEvent)
	// OnProcess, if set, sees every process start (execution prevention).
	OnProcess func(ProcessStart)
	// OnCommandLine, if set, sees every process start once its command
	// line is known (OnProcess may fire before: anti-ransomware precursors).
	OnCommandLine func(ProcessStart)
	// OnScript, if set, gets what AMSI scanned (the script scanner); the
	// AMSI session only runs when it is set.
	OnScript func(AMSIScript)
}

// FileEvent is one file create, rename or delete, before rate limiting, or a
// write (one per process and file a minute, never a SIEM line): the
// anti-ransomware heuristics (internal/ransomguard) see every one. Image may
// be empty or a bare name for a process whose start has not arrived yet.
type FileEvent struct {
	Time   time.Time
	PID    uint32
	PPID   uint32
	Image  string
	User   string
	Action string // create, write, rename, delete
	Path   string // the new name for a rename
	From   string // the old name for a rename, when known
}

type fileWindowState struct {
	start                     time.Time
	sent                      int
	creates, renames, deletes int
	sample                    string
}

// fileTracker turns Kernel-File and image load events into lines. Not safe
// for concurrent use; the sensor's run loop owns it.
type fileTracker struct {
	j    *processJoiner
	self uint32 // the agent's own PID: its journal writes are not reported
	// longPath expands the 8.3 components of an existing path (identity off Windows).
	longPath func(string) string
	now      func() time.Time
	// onFile, when set, sees every file event before the budget.
	onFile func(FileEvent)

	objects map[string]string      // FileObject -> device path of its open
	writes  map[writeKey]time.Time // a write reported to onFile -> when
	// writeObjects: FileObject -> device path, from the write session's opens
	// (two generations, prevWriteObjects the older)
	writeObjects, prevWriteObjects map[uint64]string
	// unresolvedWrites counts writes through an unknown FileObject
	unresolvedWrites uint64
	windows          map[uint32]*fileWindowState
	images           map[string]time.Time // image|dll (or driver path) -> last reported
	// deferred lines wait for their process's start, which comes through
	// another session: a short-lived child's file event often arrives first.
	deferred []deferredLine
}

// fileJoinWindow bounds how long a file or image line waits for its
// process's full image path. Longer than joinWindow: the process-start
// session's events arrive with ETW's buffer flushes, which on a busy host
// took more than 1.5 s (Image="cmd.exe" on CI); a bare name misses
// Image|endswith rules.
const fileJoinWindow = 4 * time.Second

// deferredLine is built once the process is known or fileJoinWindow has passed;
// build returns "" for a line that is not to be sent (a repeated image load).
type deferredLine struct {
	pid     uint32
	at      time.Time
	logType string
	build   func(image, user string) string
}

const maxDeferred = 4096

func newFileTracker(j *processJoiner, self uint32, longPath func(string) string) *fileTracker {
	if longPath == nil {
		longPath = func(p string) string { return p }
	}
	return &fileTracker{j: j, self: self, longPath: longPath, now: time.Now,
		objects: map[string]string{}, writes: map[writeKey]time.Time{}, writeObjects: map[uint64]string{},
		windows: map[uint32]*fileWindowState{},
		images:  map[string]time.Time{}}
}

// out is one line for the buffer.
type out struct{ logType, line string }

// file takes a Kernel-File event.
func (t *fileTracker) file(ev *etw.Event) []out {
	if ev.PID == t.self {
		return nil
	}
	switch ev.ID {
	case fileCreate:
		obj, _ := ev.Get("FileObject")
		name, _ := ev.Get("FileName")
		if obj != "" && name != "" {
			if len(t.objects) >= maxObjects {
				t.objects = map[string]string{}
			}
			t.objects[obj] = name
		}
		// An open with FILE_DELETE_ON_CLOSE deletes the file when its last
		// handle closes, without a DeletePath event.
		if opts, ok := number(ev, "CreateOptions"); ok && opts&fileDeleteOnClose != 0 && opts&fileDirectoryOp == 0 {
			return t.emit(ev.PID, "delete", t.long(t.path(name)), "")
		}
		return nil
	case fileCreateNew:
		if opts, ok := number(ev, "CreateOptions"); ok && opts&fileDirectoryOp != 0 {
			return nil
		}
		name, _ := ev.Get("FileName")
		return t.emit(ev.PID, "create", t.path(name), "")
	case fileRenamePath:
		name, _ := ev.Get("FilePath")
		obj, _ := ev.Get("FileObject")
		src := ""
		if old := t.objects[obj]; old != "" {
			src = t.long(t.path(old))
		}
		return t.emit(ev.PID, "rename", t.path(name), src)
	case fileDeletePath:
		name, _ := ev.Get("FilePath")
		return t.emit(ev.PID, "delete", t.path(name), "")
	}
	return nil
}

// writeSession takes an event of the guard's own Kernel-File session
// (writeProvider): it ships nothing. An open remembers its FileObject's name
// (in a map of its own: this session's opens are not the SIEM session's);
// a write goes to onFile as a "write" of that name, once per process and
// file per fileWindow. Writes by System (the lazy writer and paging I/O
// flushing what a process wrote earlier), by the agent and through unknown
// objects are dropped. This runs for every write on the host: a map lookup
// in the common case.
func (t *fileTracker) writeSession(ev *etw.Event) {
	if t.onFile == nil || ev.PID == t.self || ev.PID == 0 || ev.PID == 4 {
		return
	}
	switch ev.ID {
	case fileCreate:
		obj, _ := ev.Get("FileObject")
		name, _ := ev.Get("FileName")
		if v, err := strconv.ParseUint(obj, 0, 64); err == nil && v != 0 && name != "" {
			// Two generations: when the current one is full it becomes the
			// previous one, so the objects opened just before stay known
			// (a full reset lost every live object at once).
			if len(t.writeObjects) >= maxObjects {
				t.prevWriteObjects, t.writeObjects = t.writeObjects, make(map[uint64]string, maxObjects)
			}
			t.writeObjects[v] = name
		}
	case fileWrite:
		t.write(ev.PID, ev.Value)
	}
}

// write reports pid's write through FileObject obj (see writeSession).
// A write whose object is unknown (its open was missed or aged out, or the
// fast decode read nothing) is counted: unresolvedWrites.
func (t *fileTracker) write(pid uint32, obj uint64) {
	name := t.writeObjects[obj]
	if name == "" {
		name = t.prevWriteObjects[obj]
	}
	if obj == 0 || name == "" {
		t.unresolvedWrites++
		return
	}
	now := t.now()
	k := writeKey{pid, name}
	if last, ok := t.writes[k]; ok && now.Sub(last) < fileWindow {
		return
	}
	if len(t.writes) >= maxWrites {
		for k, last := range t.writes {
			if now.Sub(last) >= fileWindow {
				delete(t.writes, k)
			}
		}
		if len(t.writes) >= maxWrites {
			t.writes = map[writeKey]time.Time{}
		}
	}
	t.writes[k] = now
	target := t.path(name)
	if target == "" {
		return
	}
	if strings.Contains(target, "~") { // 8.3 components: the canaries and the guard use long names
		target = t.long(target)
	}
	t.notify(pid, "write", target, "", now)
}

// long expands 8.3 components of a drive path; share paths are left as
// they are (no network round trip on the event path).
func (t *fileTracker) long(p string) string {
	if !drivePath(p) {
		return p
	}
	return t.longPath(p)
}

// drivePath reports whether p is a drive-letter path (C:\...).
func drivePath(p string) bool { return len(p) >= 3 && p[1] == ':' && p[2] == '\\' }

// Network redirector device prefixes (lower case). SMB files come as
// \Device\Mup\server\share\...; a mapped drive adds redirector components
// starting with ';' (\Device\Mup\;LanmanRedirector\;Z:0000...\server\share).
var sharePrefixes = []string{`\device\mup\`, `\device\lanmanredirector\`}

// sharePath turns a redirector device path into \\server\share\..., or ""
// for what is not one, or a pipe or mailslot on a server.
func sharePath(device string) string {
	lower := strings.ToLower(device)
	for _, pre := range sharePrefixes {
		if !strings.HasPrefix(lower, pre) {
			continue
		}
		rest := device[len(pre):]
		for strings.HasPrefix(rest, ";") { // ;LanmanRedirector\, ;Z:0000000000012345\
			i := strings.IndexByte(rest, '\\')
			if i < 0 {
				return ""
			}
			rest = rest[i+1:]
		}
		parts := strings.SplitN(rest, `\`, 3)
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" ||
			strings.EqualFold(parts[1], "pipe") || strings.EqualFold(parts[1], "mailslot") {
			return ""
		}
		return `\\` + rest
	}
	return ""
}

// path is a drive-letter path, a \\server\share\... path for a file on a
// network share (the guard's only: SIEM lines are for drive paths, as
// before), or "" for what is not a file (named pipes, mailslots) or is
// skipped.
func (t *fileTracker) path(device string) string {
	if device == "" {
		return ""
	}
	if s := sharePath(device); s != "" {
		return s
	}
	p := t.j.dosPath(device)
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
		return ""
	}
	lower := strings.ToLower(p[2:])
	for _, s := range skipFilePrefixes {
		if strings.HasPrefix(lower, s) {
			return ""
		}
	}
	return p
}

func (t *fileTracker) emit(pid uint32, action, target, source string) []out {
	if target == "" {
		return nil
	}
	now := t.now()
	t.notify(pid, action, target, source, now)
	// Share paths reach the guard only: the SIEM lines stay what they were
	// (none for a file on a share, no share source on a rename).
	if !drivePath(target) {
		return nil
	}
	if !drivePath(source) {
		source = ""
	}
	w := t.windows[pid]
	var res []out
	if w == nil || now.Sub(w.start) >= fileWindow {
		if w != nil {
			res = append(res, t.summary(pid, w)...)
		}
		if len(t.windows) >= maxFileProcs {
			t.windows = map[uint32]*fileWindowState{}
		}
		w = &fileWindowState{start: now}
		t.windows[pid] = w
	}
	if w.sent < fileBudget {
		w.sent++
		id := 11
		if action == "delete" {
			id = 23
		}
		return append(res, t.withOwner(pid, LogTypeFile, func(image, user string) string {
			return line(id, [][2]string{
				{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-File"},
				{"ProcessId", strconv.FormatUint(uint64(pid), 10)}, {"Image", image}, {"User", user},
				{"FileAction", action}, {"TargetFilename", target}, {"SourceFilename", source},
			})
		})...)
	}
	switch action {
	case "create":
		w.creates++
	case "rename":
		w.renames++
	case "delete":
		w.deletes++
	}
	if w.sample == "" {
		w.sample = target
	}
	return res
}

// notify hands one file event to onFile, if set.
func (t *fileTracker) notify(pid uint32, action, target, source string, now time.Time) {
	if t.onFile == nil {
		return
	}
	image, user := t.j.owner(pid)
	var ppid uint32
	if p := t.j.known[pid]; p != nil {
		ppid = p.ppid
	} else if p := t.j.pending[pid]; p != nil {
		ppid = p.ppid
	}
	t.onFile(FileEvent{Time: now, PID: pid, PPID: ppid, Image: image, User: user,
		Action: action, Path: target, From: source})
}

func (t *fileTracker) summary(pid uint32, w *fileWindowState) []out {
	if w.creates+w.renames+w.deletes == 0 {
		return nil
	}
	image, user := t.j.owner(pid)
	return []out{{LogTypeFile, line(fileSummaryEvent, [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-File"},
		{"ProcessId", strconv.FormatUint(uint64(pid), 10)}, {"Image", image}, {"User", user},
		{"FileAction", "summary"}, {"Creates", strconv.Itoa(w.creates)}, {"Renames", strconv.Itoa(w.renames)},
		{"Deletes", strconv.Itoa(w.deletes)}, {"TargetFilename", w.sample},
	})}}
}

// withOwner builds the line now when pid's start was seen, else defers it.
func (t *fileTracker) withOwner(pid uint32, logType string, build func(image, user string) string) []out {
	if t.j.knows(pid) {
		return t.build(deferredLine{pid: pid, logType: logType, build: build})
	}
	var res []out
	if len(t.deferred) >= maxDeferred { // a burst: send the oldest as it is rather than grow
		res = t.build(t.deferred[0])
		t.deferred = t.deferred[1:]
	}
	t.deferred = append(t.deferred, deferredLine{pid: pid, at: t.now(), logType: logType, build: build})
	return res
}

func (t *fileTracker) build(d deferredLine) []out {
	image, user := t.j.owner(d.pid)
	if l := d.build(image, user); l != "" {
		return []out{{d.logType, l}}
	}
	return nil
}

// tick sends the deferred lines whose process is now known or that waited
// fileJoinWindow, and the summaries of file windows that have ended.
func (t *fileTracker) tick() []out {
	now := t.now()
	var res []out
	kept := t.deferred[:0]
	for _, d := range t.deferred {
		if t.j.knows(d.pid) || now.Sub(d.at) >= fileJoinWindow {
			res = append(res, t.build(d)...)
		} else {
			kept = append(kept, d)
		}
	}
	t.deferred = kept
	for pid, w := range t.windows {
		if now.Sub(w.start) >= fileWindow {
			res = append(res, t.summary(pid, w)...)
			delete(t.windows, pid)
		}
	}
	return res
}

// flushAll emits every deferred line and pending summary (the sensor is stopping).
func (t *fileTracker) flushAll() []out {
	var res []out
	for _, d := range t.deferred {
		res = append(res, t.build(d)...)
	}
	t.deferred = nil
	for pid, w := range t.windows {
		res = append(res, t.summary(pid, w)...)
		delete(t.windows, pid)
	}
	return res
}

// image takes a Kernel-Process ImageLoad event.
func (t *fileTracker) image(ev *etw.Event) []out {
	if ev.ID != imageLoadEvent {
		return nil
	}
	pid, ok := number(ev, "ProcessID")
	if !ok {
		pid = ev.PID
	}
	if pid == t.self && pid != 0 {
		return nil
	}
	name, _ := ev.Get("ImageName")
	loaded := t.j.dosPath(name)
	if loaded == "" {
		return nil
	}
	if pid == 0 || pid == 4 {
		if !t.firstSeen("driver|" + strings.ToLower(loaded)) {
			return nil
		}
		return []out{{LogTypeImage, line(6, [][2]string{
			{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Process"}, {"ImageLoaded", loaded},
		})}}
	}
	return t.withOwner(pid, LogTypeImage, func(image, user string) string {
		if !t.firstSeen(strings.ToLower(image) + "|" + strings.ToLower(loaded)) {
			return ""
		}
		return line(7, [][2]string{
			{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Process"},
			{"ProcessId", strconv.FormatUint(uint64(pid), 10)}, {"Image", image}, {"User", user},
			{"ImageLoaded", loaded},
		})
	})
}

// firstSeen reports whether key was not reported within imageDedupe, and
// records it.
func (t *fileTracker) firstSeen(key string) bool {
	now := t.now()
	if last, ok := t.images[key]; ok && now.Sub(last) < imageDedupe {
		return false
	}
	if len(t.images) >= maxImagePairs {
		for k, last := range t.images {
			if now.Sub(last) >= imageDedupe {
				delete(t.images, k)
			}
		}
		if len(t.images) >= maxImagePairs {
			t.images = map[string]time.Time{}
		}
	}
	t.images[key] = now
	return true
}
