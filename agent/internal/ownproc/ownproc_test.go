package ownproc

import (
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	r := New()
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	r.Add(42)
	if !r.Has(42) || r.Has(43) {
		t.Fatal("Has")
	}
	r.Done(42)
	now = now.Add(keepAfterExit - time.Second)
	if !r.Has(42) {
		t.Fatal("kept a while after exit: its children's events arrive late")
	}
	now = now.Add(2 * time.Second)
	if r.Has(42) {
		t.Fatal("forgotten after keepAfterExit")
	}
	for i := 0; i < 2*maxEntries; i++ {
		r.Add(uint32(1000 + i))
	}
	if n := r.len(); n > maxEntries {
		t.Fatalf("unbounded: %d", n)
	}
}

func TestRunRecordsTheChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/true")
	}
	var pid int
	cmd := exec.Command("/bin/true")
	if err := Run(cmd); err != nil {
		t.Fatal(err)
	}
	pid = cmd.Process.Pid
	if !Has(uint32(pid)) {
		t.Fatal("the child is not recorded")
	}
	out, err := Output(exec.Command("/bin/echo", "hi"))
	if err != nil || string(out) != "hi\n" {
		t.Fatalf("Output = %q, %v", out, err)
	}
}
