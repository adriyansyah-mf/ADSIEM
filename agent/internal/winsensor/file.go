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
// Reads, writes and closes never reach the agent.
const kernelFileKeywords = 0x10 | 0x80 | 0x400 | 0x800 | 0x1000

var fileEventIDs = []uint16{fileCreate, fileDeletePath, fileRenamePath, fileCreateNew}

// Microsoft-Windows-Kernel-Process ImageLoad (WINEVENT_KEYWORD_IMAGE): ProcessID,
// ImageName (an NT device path). A load into PID 0 or 4 is a kernel driver.
const (
	imageLoadEvent  = 5
	imageKeyword    = 0x40
	fileDirectoryOp = 0x1 // FILE_DIRECTORY_FILE in CreateOptions
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

	objects map[string]string // FileObject -> device path of its open
	windows map[uint32]*fileWindowState
	images  map[string]time.Time // image|dll (or driver path) -> last reported
}

func newFileTracker(j *processJoiner, self uint32, longPath func(string) string) *fileTracker {
	if longPath == nil {
		longPath = func(p string) string { return p }
	}
	return &fileTracker{j: j, self: self, longPath: longPath, now: time.Now,
		objects: map[string]string{}, windows: map[uint32]*fileWindowState{}, images: map[string]time.Time{}}
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
			src = t.longPath(t.path(old))
		}
		return t.emit(ev.PID, "rename", t.path(name), src)
	case fileDeletePath:
		name, _ := ev.Get("FilePath")
		return t.emit(ev.PID, "delete", t.path(name), "")
	}
	return nil
}

// path is a drive-letter path, or "" for what is not a file on a volume
// (named pipes, mailslots, network redirector paths) or is skipped.
func (t *fileTracker) path(device string) string {
	if device == "" {
		return ""
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
		image, user := t.j.owner(pid)
		id := 11
		if action == "delete" {
			id = 23
		}
		return append(res, out{LogTypeFile, line(id, [][2]string{
			{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-File"},
			{"ProcessId", strconv.FormatUint(uint64(pid), 10)}, {"Image", image}, {"User", user},
			{"FileAction", action}, {"TargetFilename", target}, {"SourceFilename", source},
		})})
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

// tick flushes the summaries of file windows that have ended.
func (t *fileTracker) tick() []out {
	now := t.now()
	var res []out
	for pid, w := range t.windows {
		if now.Sub(w.start) >= fileWindow {
			res = append(res, t.summary(pid, w)...)
			delete(t.windows, pid)
		}
	}
	return res
}

// flushAll emits every pending summary (the sensor is stopping).
func (t *fileTracker) flushAll() []out {
	var res []out
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
	image, user := t.j.owner(pid)
	if !t.firstSeen(strings.ToLower(image) + "|" + strings.ToLower(loaded)) {
		return nil
	}
	return []out{{LogTypeImage, line(7, [][2]string{
		{"Channel", "ETW"}, {"Provider", "Microsoft-Windows-Kernel-Process"},
		{"ProcessId", strconv.FormatUint(uint64(pid), 10)}, {"Image", image}, {"User", user},
		{"ImageLoaded", loaded},
	})}}
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
