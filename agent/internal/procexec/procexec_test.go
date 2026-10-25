//go:build linux

package procexec

import (
	"encoding/binary"
	"testing"
)

// record builds struct exec_event as bpf/execve.bpf.c lays it out.
func record(args string, argsSize uint32, truncated bool) []byte {
	b := make([]byte, recordMinSize+7) // the kernel pads the struct to 8 bytes
	le := binary.LittleEndian
	le.PutUint32(b[8:], 42)    // pid
	le.PutUint32(b[12:], 1)    // ppid
	le.PutUint32(b[16:], 1000) // uid
	copy(b[24:], "ls")
	copy(b[40:], "/usr/bin/ls")
	copy(b[40+filenameLen:], "/usr/bin/bash")
	args0 := 40 + 2*filenameLen
	copy(b[args0:], args)
	le.PutUint32(b[args0+argsBufLen:], argsSize)
	le.PutUint32(b[args0+argsBufLen+4:], 2)
	if truncated {
		b[args0+argsBufLen+8] = 1
	}
	return b
}

// The ring buffer is not zeroed: bytes past args_size belong to an older
// event and must not leak into CommandLine. Before argsBufLen matched the
// C struct (1024), args_size was read from the middle of argv.
func TestDecodeEventUsesArgsSize(t *testing.T) {
	stale := "ls\x00-la\x00" + "rm\x00-rf\x00/old/event\x00"
	got, ok := decodeEvent(record(stale, uint32(len("ls\x00-la\x00")), false))
	if !ok {
		t.Fatal("decode failed")
	}
	want := `Image="/usr/bin/ls" CommandLine="ls -la" PID=42 PPID=1 User=1000 ParentImage="/usr/bin/bash" Comm="ls"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestDecodeEventLongCommandLine(t *testing.T) {
	var args []byte
	for len(args) < 900 {
		args = append(args, []byte("argument-of-some-length\x00")...)
	}
	got, ok := decodeEvent(record(string(args), uint32(len(args)), true))
	if !ok {
		t.Fatal("decode failed")
	}
	if len(got) < 900 {
		t.Fatalf("command line cut short (%d bytes): %s", len(got), got)
	}
	if want := " ArgsTruncated=true"; got[len(got)-len(want):] != want {
		t.Fatalf("truncation flag lost: %s", got[len(got)-40:])
	}
}

func TestDecodeEventShortRecord(t *testing.T) {
	if _, ok := decodeEvent(make([]byte, recordMinSize-1)); ok {
		t.Fatal("short record accepted")
	}
}
