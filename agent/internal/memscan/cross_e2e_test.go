//go:build linux

package memscan

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/yara"
	"golang.org/x/sys/unix"
)

// Reading another process needs root (ptrace access). Run with
// MEMSCAN_E2E=1 as root; CI does under sudo.

func TestMain(m *testing.M) {
	if marker := os.Getenv("MEMSCAN_HOLD"); marker != "" {
		// A "victim": the marker on its heap and an RWX mapping, like an
		// injected payload, then wait to be scanned.
		held := []byte("<<" + marker + ">>")
		rwx, _ := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, unix.MAP_PRIVATE|unix.MAP_ANON)
		copy(rwx, "\xfc\x48\x83\xe4\xf0"+marker)
		os.Stdout.WriteString("ready\n")
		time.Sleep(30 * time.Second)
		_ = held
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestScanOtherProcess(t *testing.T) {
	if os.Getenv("MEMSCAN_E2E") != "1" {
		t.Skip("set MEMSCAN_E2E=1 (needs root)")
	}
	marker := "cross-process-marker-" + strconv.Itoa(os.Getpid())
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "MEMSCAN_HOLD="+marker)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	if line, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(line) != "ready" {
		t.Fatalf("victim said %q", line)
	}
	pid := cmd.Process.Pid

	rules, err := yara.Compile(`rule shellcode_marker { strings: $m = "` + marker + `" $sc = { FC 48 83 E4 F0 } condition: any of them }`)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(context.Background(), rules, pid, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var inRWX bool
	for _, m := range res.Matches {
		if m.Region.Suspicious() {
			inRWX = true
		}
	}
	if len(res.Matches) < 2 || !inRWX {
		t.Fatalf("want the marker on the heap and in the RWX region; got %+v", res.Matches)
	}
	sus, err := SuspiciousRegions(pid)
	if err != nil || len(sus) == 0 {
		t.Fatalf("RWX region not found: %v %v", sus, err)
	}

	var lines []string
	s := &Sweeper{Push: func(_, l string) { lines = append(lines, l) }}
	s.Sweep()
	found := false
	for _, l := range lines {
		found = found || strings.Contains(l, "PID="+strconv.Itoa(pid)+" ")
	}
	if !found {
		t.Fatalf("sweep did not report the victim: %q", lines)
	}
}
