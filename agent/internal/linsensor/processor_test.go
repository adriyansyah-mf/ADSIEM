package linsensor

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

type fakeProc struct {
	exe map[uint32]string
	cwd map[uint32]string
	fd  map[int32]string
}

func (f fakeProc) Exe(tgid uint32) string       { return f.exe[tgid] }
func (f fakeProc) Cwd(_, tgid uint32) string    { return f.cwd[tgid] }
func (f fakeProc) FD(_ uint32, fd int32) string { return f.fd[fd] }

type sink struct{ lines []string }

func (s *sink) push(logType, line string) { s.lines = append(s.lines, logType+" "+line) }

func newTestProcessor(proc fakeProc, disabled ...string) (*processor, *sink, *[]FileEvent, *time.Time) {
	var s sink
	var files []FileEvent
	d := map[string]bool{}
	for _, g := range disabled {
		d[g] = true
	}
	p := newProcessor(s.push, func(f FileEvent) { files = append(files, f) }, d, proc)
	now := time.Unix(1000, 0)
	p.now = func() time.Time { return now }
	return p, &s, &files, &now
}

func TestDecodeRawLayout(t *testing.T) {
	b := make([]byte, recordSize)
	le := binary.LittleEndian
	ret := int64(-2)
	le.PutUint64(b[8:], uint64(ret))
	le.PutUint64(b[16:], 0o101)
	le.PutUint32(b[40:], kindOpen)
	le.PutUint32(b[44:], 11)
	le.PutUint32(b[48:], 10)
	le.PutUint32(b[52:], 1)
	le.PutUint32(b[56:], 1000)
	le.PutUint32(b[64:], uint32(0xffffff9c)) // AT_FDCWD
	copy(b[72:], "touch")
	copy(b[88:], "a.txt")
	copy(b[88+3*pathLen:], "/dir2")
	copy(b[88+2*pathLen:], "/home/u")
	ev, ok := decodeRaw(b)
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.kind != kindOpen || ev.pid != 11 || ev.tgid != 10 || ev.ppid != 1 || ev.uid != 1000 || ev.ret != -2 ||
		ev.arg0 != 0o101 || ev.dfd != atFDCWD || ev.comm != "touch" || ev.path != "a.txt" || ev.dir != "/home/u" || ev.dir2 != "/dir2" {
		t.Fatalf("decoded %+v", ev)
	}
	if _, ok := decodeRaw(b[:recordSize-1]); ok {
		t.Fatal("a short record must be rejected")
	}
}

func TestFileEventsResolveAndReport(t *testing.T) {
	p, s, files, _ := newTestProcessor(fakeProc{
		exe: map[uint32]string{10: "/usr/bin/vim"},
		cwd: map[uint32]string{10: "/proc-cwd"},
		fd:  map[int32]string{5: "/srv/data"},
	})
	p.handle(rawEvent{kind: kindOpen, tgid: 10, pid: 10, path: "notes.txt", dir: "/home/u", dfd: atFDCWD, arg0: oCreat | oWronly, comm: "vim"})
	p.handle(rawEvent{kind: kindOpen, tgid: 10, pid: 10, path: "x.db", dfd: 5, arg0: oRdwr, comm: "vim"})
	p.handle(rawEvent{kind: kindRename, tgid: 10, pid: 10, path: "a", dir: "/k", path2: "/abs/b", dfd: atFDCWD, comm: "vim"})
	p.handle(rawEvent{kind: kindUnlink, tgid: 10, pid: 10, path: "old", dfd: atFDCWD, arg0: atRemovDir, comm: "vim"})
	want := []string{
		`linux_file_event action=create TargetFilename="/home/u/notes.txt" Image="/usr/bin/vim" Comm="vim" PID=10 PPID=0 User=0`,
		`linux_file_event action=write TargetFilename="/srv/data/x.db" Image="/usr/bin/vim"`,
		`linux_file_event action=rename TargetFilename="/abs/b" SourceFilename="/k/a" Image="/usr/bin/vim"`,
		`linux_file_event action=delete TargetFilename="/proc-cwd/old" IsDirectory=true`,
	}
	if len(s.lines) != len(want) {
		t.Fatalf("lines = %q", s.lines)
	}
	for i, w := range want {
		if !strings.HasPrefix(s.lines[i], w) {
			t.Errorf("line %d:\n got  %s\n want %s...", i, s.lines[i], w)
		}
	}
	if len(*files) != 4 || (*files)[2].From != "/k/a" || !(*files)[3].Dir {
		t.Fatalf("OnFile saw %+v", *files)
	}
}

func TestPseudoFilesystemsSkipped(t *testing.T) {
	p, s, files, _ := newTestProcessor(fakeProc{})
	for _, path := range []string{"/proc/1/attr", "/sys/fs/cgroup/x", "/dev/null", "/run/lock/x", "/var/run/x.pid"} {
		p.handle(rawEvent{kind: kindOpen, tgid: 1, path: path, arg0: oWronly})
	}
	p.handle(rawEvent{kind: kindOpen, tgid: 1, path: "/dev/shm/payload", arg0: oWronly})
	if len(s.lines) != 1 || !strings.Contains(s.lines[0], "/dev/shm/payload") || len(*files) != 1 {
		t.Fatalf("lines = %q", s.lines)
	}
}

func TestFileBudgetSummarizes(t *testing.T) {
	p, s, files, now := newTestProcessor(fakeProc{exe: map[uint32]string{7: "/usr/bin/tar"}})
	for i := 0; i < fileBudget+20; i++ {
		p.handle(rawEvent{kind: kindOpen, tgid: 7, path: "/data/f" + string(rune('a'+i%26)) + strings.Repeat("x", i), arg0: oCreat})
	}
	for i := 0; i < 5; i++ {
		p.handle(rawEvent{kind: kindRename, tgid: 7, path: "/data/r", path2: "/data/r.locked" + strings.Repeat("y", i)})
	}
	if len(s.lines) != fileBudget {
		t.Fatalf("shipped %d lines in the window, want %d", len(s.lines), fileBudget)
	}
	if len(*files) != fileBudget+25 {
		t.Fatalf("OnFile must see every event: %d", len(*files))
	}
	*now = now.Add(fileWindow)
	p.tick()
	last := s.lines[len(s.lines)-1]
	if !strings.HasPrefix(last, `linux_file_event action=summary Writes=20 Renames=5 Deletes=0`) || !strings.Contains(last, `Image="/usr/bin/tar"`) {
		t.Fatalf("summary = %s", last)
	}
	// A new window starts fresh.
	p.handle(rawEvent{kind: kindOpen, tgid: 7, path: "/data/new", arg0: oCreat})
	if !strings.Contains(s.lines[len(s.lines)-1], "/data/new") {
		t.Fatal("events after the window must ship again")
	}
}

func TestDuplicateFileEventsDropped(t *testing.T) {
	p, s, _, _ := newTestProcessor(fakeProc{})
	for i := 0; i < 3; i++ {
		p.handle(rawEvent{kind: kindOpen, tgid: 3, path: "/var/log/app.log", arg0: oWronly})
	}
	if len(s.lines) != 1 {
		t.Fatalf("lines = %q", s.lines)
	}
}

func TestImageFromExecSurvivesExit(t *testing.T) {
	p, s, _, _ := newTestProcessor(fakeProc{}) // /proc knows nothing: the process is gone
	p.handle(rawEvent{kind: kindExec, tgid: 20, path: "/usr/bin/mv"})
	p.handle(rawEvent{kind: kindRename, tgid: 20, path: "/a", path2: "/b", comm: "mv"})
	p.handle(rawEvent{kind: kindExit, tgid: 20, comm: "mv", arg0: 3 << 8})
	if !strings.Contains(s.lines[0], `Image="/usr/bin/mv"`) {
		t.Fatalf("file line = %s", s.lines[0])
	}
	if !strings.HasPrefix(s.lines[1], `linux_process_exit ExitCode=3 Signal=0 Image="/usr/bin/mv"`) {
		t.Fatalf("exit line = %s", s.lines[1])
	}
	p.handle(rawEvent{kind: kindExit, tgid: 21, comm: "x", arg0: 9})
	if !strings.HasPrefix(s.lines[2], `linux_process_exit ExitCode=-1 Signal=9 Image="x"`) {
		t.Fatalf("killed exit = %s", s.lines[2])
	}
	if _, ok := p.images[20]; ok {
		t.Fatal("image cache must forget an exited process")
	}
}

func TestSecurityEvents(t *testing.T) {
	p, s, _, now := newTestProcessor(fakeProc{exe: map[uint32]string{30: "/tmp/x", 31: "/usr/sbin/sshd", 1: "/sbin/init"}})
	p.handle(rawEvent{kind: kindPtrace, tgid: 30, arg0: 16, arg1: 31, comm: "x"})
	p.handle(rawEvent{kind: kindPtrace, tgid: 30, arg0: 16, arg1: 31, comm: "x"}) // deduped
	p.handle(rawEvent{kind: kindSetID, tgid: 30, ppid: 1, uid: 1000, euid: 0, arg0: 3, arg1: 0 | 0xffffffff<<32, arg2: 0, comm: "x"})
	p.handle(rawEvent{kind: kindCapset, tgid: 30, ppid: 1, uid: 1000, arg0: 0x200000, arg1: 0x200000, comm: "x"})
	p.handle(rawEvent{kind: kindModuleFinit, tgid: 30, path: "/rootkit.ko", path2: "", comm: "insmod"})
	p.handle(rawEvent{kind: kindModuleInit, tgid: 30, arg0: 4096, comm: "x"})
	p.handle(rawEvent{kind: kindMemfd, tgid: 30, path: "p", comm: "x"})
	p.handle(rawEvent{kind: kindMemfd, tgid: 30, path: "p", comm: "x"}) // deduped
	p.handle(rawEvent{kind: kindFilelessExec, tgid: 32, ppid: 30, path: "/memfd:p", path2: "/proc/self/fd/3", arg0: 0, comm: "3"})
	want := []string{
		`linux_ptrace action=attach TargetPID=31 TargetImage="/usr/sbin/sshd" Image="/tmp/x"`,
		`linux_privilege_change action=setresuid IDs="0,-1,0" Image="/tmp/x" Comm="x" PID=30 PPID=1 User=1000 EUID=0 ParentImage="/sbin/init"`,
		`linux_privilege_change action=capset Effective=0x200000 Permitted=0x200000`,
		`linux_kernel_module action=load Module="/rootkit.ko" Params=""`,
		`linux_kernel_module action=load_memory Size=4096`,
		`linux_memfd_create MemfdName="p" Flags=0x0 Image="/tmp/x"`,
		`linux_fileless_exec Image="/memfd:p" ExecPath="/proc/self/fd/3" Links=0 Comm="3" PID=32 PPID=30 User=0 EUID=0 ParentImage="/tmp/x"`,
	}
	if len(s.lines) != len(want) {
		t.Fatalf("lines = %q", s.lines)
	}
	for i, w := range want {
		if !strings.HasPrefix(s.lines[i], w) {
			t.Errorf("line %d:\n got  %s\n want %s...", i, s.lines[i], w)
		}
	}
	*now = now.Add(ptraceDedupe)
	p.handle(rawEvent{kind: kindPtrace, tgid: 30, arg0: 16, arg1: 31, comm: "x"})
	if len(s.lines) != len(want)+1 {
		t.Fatal("ptrace dedupe must expire")
	}
}

func TestDisabledGroups(t *testing.T) {
	p, s, files, _ := newTestProcessor(fakeProc{}, GroupFile, GroupExit, GroupMemfd, GroupPtrace, GroupModule, GroupPrivilege)
	for _, k := range []uint32{kindOpen, kindExit, kindMemfd, kindPtrace, kindModuleInit, kindSetID} {
		p.handle(rawEvent{kind: k, tgid: 5, path: "/x", arg0: oWronly})
	}
	if len(s.lines) != 0 || len(*files) != 0 {
		t.Fatalf("disabled groups reported: %q", s.lines)
	}
	p.handle(rawEvent{kind: kindFilelessExec, tgid: 5, path: "/memfd:x"})
	if len(s.lines) != 1 {
		t.Fatal("fileless exec is always reported")
	}
}

func TestKVEscapes(t *testing.T) {
	if got := kv("a\"b\\c\nd"); got != `"a\"b\\c\nd"` {
		t.Fatalf("kv = %s", got)
	}
}
