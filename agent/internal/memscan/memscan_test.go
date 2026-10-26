//go:build linux || windows

package memscan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/yara"
)

// The tests read this process's own memory: no root needed on Linux, no
// SeDebugPrivilege on Windows.

func TestScanFindsMarkerInOwnMemory(t *testing.T) {
	b := make([]byte, 8)
	rand.Read(b)
	marker := "memscan-marker-" + hex.EncodeToString(b)
	// Keep the marker on the heap (not only in the rule text).
	held := []byte(strings.Repeat("x", 100) + marker + strings.Repeat("y", 100))
	rules, err := yara.Compile(`rule mem { strings: $m = "` + marker + `" condition: $m }`)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(context.Background(), rules, os.Getpid(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Regions == 0 || res.Bytes == 0 {
		t.Fatalf("nothing scanned: %+v", res)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("marker not found in %d regions (%d bytes, %d skipped)", res.Regions, res.Bytes, res.Skipped)
	}
	m := res.Matches[0]
	if m.Rule != "mem" || m.Address < m.Region.Start || m.Address >= m.Region.End || !strings.Contains(m.Strings[0], marker) {
		t.Fatalf("match = %+v", m)
	}
	if !strings.HasPrefix(m.Strings[0], "$m@0x") {
		t.Fatalf("string not addressed virtually: %s", m.Strings[0])
	}
	_ = held[0]
}

func TestLimits(t *testing.T) {
	rules, _ := yara.Compile(`rule never { strings: $a = "zzzz-not-there-zzzz-1" condition: $a and false }`)
	res, err := Scan(context.Background(), rules, os.Getpid(), Limits{Chunk: 4096, MaxTotal: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes > 1<<20 || res.Skipped == 0 {
		t.Fatalf("limits not applied: %+v", res)
	}
}

func TestSuspiciousRegionFound(t *testing.T) {
	addr, size, free := allocRWX(t)
	defer free()
	regions, err := SuspiciousRegions(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range regions {
		if addr >= r.Start && addr < r.End {
			if r.Perms != "rwx" || r.Size() < size {
				t.Fatalf("region = %+v", r)
			}
			return
		}
	}
	t.Fatalf("RWX allocation at %x not reported: %+v", addr, regions)
}

func TestSweepReportsOncePerRegion(t *testing.T) {
	var lines []string
	s := &Sweeper{Push: func(_, l string) { lines = append(lines, l) }}
	line := RWXLine(Proc{PID: 42, Image: `C:\x\inj.exe`}, Region{Start: 0x10000, End: 0x11000, Perms: "rwx", Kind: "private"})
	if line != `Image="C:\\x\\inj.exe" PID=42 Address=0x10000 Size=4096 Perms=rwx Kind=private Path=""` {
		t.Fatalf("line = %s", line)
	}
	current := []Region{{Start: 0x10000, End: 0x11000, Perms: "rwx", Kind: "private"}}
	s.procs = func() ([]Proc, error) { return []Proc{{PID: 42, Image: "inj"}}, nil }
	s.regions = func(int) ([]Region, error) { return current, nil }
	if s.Sweep() != 1 || s.Sweep() != 0 {
		t.Fatalf("lines = %q", lines)
	}
	current = append(current, Region{Start: 0x20000, End: 0x21000, Perms: "rwx", Kind: "private"})
	if s.Sweep() != 1 {
		t.Fatal("a new region must be reported")
	}
	current = current[1:] // the first one went away and comes back
	s.Sweep()
	current = append(current, Region{Start: 0x10000, End: 0x11000, Perms: "rwx", Kind: "private"})
	if s.Sweep() != 1 {
		t.Fatal("a region that came back must be reported again")
	}
}

func TestRegionClassification(t *testing.T) {
	cases := []struct {
		r    Region
		want bool
	}{
		{Region{Perms: "rwx", Kind: "anon"}, true},
		{Region{Perms: "rwx", Kind: "private"}, true},
		{Region{Perms: "rwx", Kind: "heap"}, true},
		{Region{Perms: "rwx", Kind: "file"}, false},
		{Region{Perms: "rwx", Kind: "image"}, false},
		{Region{Perms: "r-x", Kind: "anon"}, false},
		{Region{Perms: "rw-", Kind: "anon"}, false},
	}
	for _, c := range cases {
		if c.r.Suspicious() != c.want {
			t.Errorf("%+v: Suspicious() = %t", c.r, !c.want)
		}
	}
}
