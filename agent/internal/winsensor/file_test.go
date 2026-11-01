package winsensor

import (
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

// Kernel-File events as etw.TestFileAndImageSources recorded them on the
// Windows runner: create, then rename (only the new name, the old one from
// the open of the same FileObject, in 8.3 form), then delete.
func kf(id uint16, pid uint32, props ...string) *etw.Event {
	ev := &etw.Event{ID: id, PID: pid, Provider: kernelFileProvider}
	for i := 0; i+1 < len(props); i += 2 {
		ev.Props = append(ev.Props, etw.Property{Name: props[i], Value: props[i+1]})
	}
	return ev
}

const vol = `\Device\HarddiskVolume3`

func newTestTracker() (*fileTracker, *time.Time) {
	j := newProcessJoiner(func(uint32) string { return `C:\Tools\locker.exe` },
		func(p string) string {
			if strings.HasPrefix(p, vol+`\`) {
				return "C:" + p[len(vol):]
			}
			return p
		})
	now := time.Unix(1000, 0)
	tr := newFileTracker(j, 99, func(p string) string { return strings.Replace(p, `RUNNER~1`, `runneradmin`, 1) })
	tr.now = func() time.Time { return now }
	return tr, &now
}

func TestFileCreateRenameDelete(t *testing.T) {
	tr, _ := newTestTracker()
	if got := tr.file(kf(fileCreate, 7, "FileObject", "0xA", "FileName", vol+`\Users\RUNNER~1\doc.txt`)); got != nil {
		t.Fatalf("an open is only remembered: %v", got)
	}
	got := tr.file(kf(fileCreateNew, 7, "FileObject", "0xA", "CreateOptions", "0x3000060", "FileName", vol+`\Users\runneradmin\doc.txt`))
	want := `EventID=11 Channel="ETW" Provider="Microsoft-Windows-Kernel-File" ProcessId="7" Image="C:\Tools\locker.exe" ` +
		`FileAction="create" TargetFilename="C:\Users\runneradmin\doc.txt"`
	if len(got) != 1 || got[0].logType != LogTypeFile || got[0].line != want {
		t.Fatalf("create = %v\nwant %s", got, want)
	}
	tr.file(kf(fileCreate, 7, "FileObject", "0xB", "FileName", vol+`\Users\RUNNER~1\doc.txt`))
	got = tr.file(kf(fileRenamePath, 7, "FileObject", "0xB", "FilePath", vol+`\Users\runneradmin\doc.txt.locked`))
	if len(got) != 1 || !strings.Contains(got[0].line, `FileAction="rename" TargetFilename="C:\Users\runneradmin\doc.txt.locked" SourceFilename="C:\Users\runneradmin\doc.txt"`) ||
		!strings.HasPrefix(got[0].line, "EventID=11 ") {
		t.Fatalf("rename = %v", got)
	}
	got = tr.file(kf(fileDeletePath, 7, "FileObject", "0xC", "FilePath", vol+`\Users\runneradmin\doc.txt.locked`))
	if len(got) != 1 || !strings.HasPrefix(got[0].line, "EventID=23 ") || !strings.Contains(got[0].line, `FileAction="delete"`) {
		t.Fatalf("delete = %v", got)
	}
}

func TestFileSkips(t *testing.T) {
	tr, _ := newTestTracker()
	for name, ev := range map[string]*etw.Event{
		"directory":   kf(fileCreateNew, 7, "CreateOptions", "0x2200021", "FileName", vol+`\Temp\dir`),
		"agent":       kf(fileCreateNew, 99, "FileName", vol+`\ProgramData\SIEMAgent\journal.dat`),
		"named pipe":  kf(fileCreateNew, 7, "FileName", `\Device\NamedPipe\x`),
		"prefetch":    kf(fileCreateNew, 7, "FileName", vol+`\Windows\Prefetch\CMD.EXE-1.pf`),
		"no filename": kf(fileDeletePath, 7),
	} {
		if got := tr.file(ev); got != nil {
			t.Errorf("%s: reported %v", name, got)
		}
	}
}

func TestFileBudgetAndSummary(t *testing.T) {
	tr, now := newTestTracker()
	lines := 0
	for i := 0; i < fileBudget+15; i++ {
		lines += len(tr.file(kf(fileDeletePath, 7, "FilePath", vol+`\data\f`+string(rune('a'+i%26)))))
	}
	if lines != fileBudget {
		t.Fatalf("%d lines in a window, budget %d", lines, fileBudget)
	}
	if got := tr.tick(); got != nil {
		t.Fatalf("summary before the window ended: %v", got)
	}
	*now = now.Add(fileWindow)
	got := tr.tick()
	if len(got) != 1 || !strings.HasPrefix(got[0].line, "EventID=1100 ") || !strings.Contains(got[0].line, `Deletes="15"`) {
		t.Fatalf("summary = %v", got)
	}
}

func TestImageAndDriverLoads(t *testing.T) {
	tr, now := newTestTracker()
	dll := func(pid string, name string) *etw.Event {
		return &etw.Event{ID: imageLoadEvent, PID: 5, Props: []etw.Property{{Name: "ProcessID", Value: pid}, {Name: "ImageName", Value: name}}}
	}
	got := tr.image(dll("6796", vol+`\Users\a\evil.dll`))
	want := `EventID=7 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ProcessId="6796" Image="C:\Tools\locker.exe" ImageLoaded="C:\Users\a\evil.dll"`
	if len(got) != 1 || got[0].logType != LogTypeImage || got[0].line != want {
		t.Fatalf("image load = %v\nwant %s", got, want)
	}
	if got := tr.image(dll("6796", vol+`\Users\a\EVIL.dll`)); got != nil {
		t.Fatalf("the same image/DLL pair is reported once a day: %v", got)
	}
	*now = now.Add(imageDedupe)
	if got := tr.image(dll("6796", vol+`\Users\a\evil.dll`)); len(got) != 1 {
		t.Fatalf("pair not reported again after a day: %v", got)
	}
	got = tr.image(dll("0", `\SystemRoot\System32\drivers\rootkit.sys`))
	if len(got) != 1 || got[0].line != `EventID=6 Channel="ETW" Provider="Microsoft-Windows-Kernel-Process" ImageLoaded="\SystemRoot\System32\drivers\rootkit.sys"` {
		t.Fatalf("driver load = %v", got)
	}
	if got := tr.image(dll("99", vol+`\Windows\System32\x.dll`)); got != nil {
		t.Fatalf("the agent's own loads are reported: %v", got)
	}
}
