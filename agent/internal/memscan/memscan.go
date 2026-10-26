// Package memscan reads process memory: YARA scans of a process's regions
// (live response) and the search for writable and executable private
// memory, where injected code and unpacked payloads live.
package memscan

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/siem-platform/agent/internal/yara"
)

// Region is one mapping of a process's address space.
type Region struct {
	Start, End uint64
	Perms      string // "rwx" letters, '-' for missing
	Kind       string // anon, heap, stack, file (Linux); private, image, mapped (Windows)
	Path       string // backing file, if any
}

func (r Region) Size() uint64     { return r.End - r.Start }
func (r Region) Readable() bool   { return strings.HasPrefix(r.Perms, "r") }
func (r Region) Executable() bool { return len(r.Perms) > 2 && r.Perms[2] == 'x' }
func (r Region) Writable() bool   { return len(r.Perms) > 1 && r.Perms[1] == 'w' }

// Suspicious reports writable+executable memory not backed by a file:
// shellcode, reflective loaders and unpackers allocate it; legitimate
// users are mostly JIT compilers.
func (r Region) Suspicious() bool {
	return r.Writable() && r.Executable() && r.Kind != "file" && r.Kind != "image" && r.Kind != "mapped"
}

// Proc is a running process.
type Proc struct {
	PID   int
	Image string
}

// Limits bound one process scan.
type Limits struct {
	// Chunk is the largest buffer scanned at once (default 16 MiB): a
	// bigger region (a heap arena) is read in chunks that overlap by
	// Overlap bytes (default 64 KiB), so a string shorter than that is
	// found across a boundary.
	Chunk, Overlap int64
	MaxTotal       int64 // bytes read per process (default 1 GiB)
	AnonOnly       bool  // skip file-backed regions (libraries, mapped files)
}

func (l *Limits) defaults() {
	if l.Chunk <= 0 {
		l.Chunk = 16 << 20
	}
	if l.Overlap <= 0 || l.Overlap >= l.Chunk {
		l.Overlap = min(64<<10, l.Chunk/2)
	}
	if l.MaxTotal <= 0 {
		l.MaxTotal = 1 << 30
	}
}

// Match is a rule that matched in one region; addresses are virtual.
type Match struct {
	Rule, Namespace string
	Tags            []string
	Address         uint64 // first string match, or the region start
	Region          Region
	Strings         []string // "$id@0xaddr: data"
}

// Result of scanning one process.
type Result struct {
	PID      int
	Image    string
	Regions  int
	Bytes    int64
	Skipped  int
	Matches  []Match
	Warnings []string
}

func hexAddr(a uint64) string { return "0x" + strconv.FormatUint(a, 16) }

func printable(b []byte) string {
	q := strconv.QuoteToASCII(string(b))
	return q[1 : len(q)-1]
}

// Scan runs rules over every readable region of pid within lim. Each
// region (or chunk of a large one) is scanned as its own buffer: filesize
// is its size, and the pe/elf modules see a mapped image when it starts
// one.
func Scan(ctx context.Context, rules *yara.Rules, pid int, lim Limits) (Result, error) {
	lim.defaults()
	res := Result{PID: pid, Image: ProcessImage(pid)}
	regions, err := Regions(pid)
	if err != nil {
		return res, err
	}
	rd, err := Open(pid)
	if err != nil {
		return res, err
	}
	defer rd.Close()
	for _, r := range regions {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if !r.Readable() || (lim.AnonOnly && (r.Kind == "file" || r.Kind == "image" || r.Kind == "mapped")) {
			continue
		}
		if res.Bytes >= lim.MaxTotal {
			res.Skipped++
			continue
		}
		res.Regions++
		seen := map[string]bool{} // a match in an overlap is found twice
		for start := r.Start; start < r.End && res.Bytes < lim.MaxTotal; start += uint64(lim.Chunk - lim.Overlap) {
			size := min(int64(r.End-start), lim.Chunk, lim.MaxTotal-res.Bytes)
			buf := make([]byte, size)
			n, _ := rd.ReadAt(buf, start)
			if n == 0 {
				res.Skipped++
				break
			}
			res.Bytes += int64(n)
			sr, err := rules.Scan(ctx, buf[:n])
			if err != nil {
				return res, err
			}
			res.Warnings = append(res.Warnings, sr.Warnings...)
			for _, m := range sr.Matches {
				mm := Match{Rule: m.Rule, Namespace: m.Namespace, Tags: m.Tags, Address: start, Region: r}
				for i, s := range m.Strings {
					addr := start + uint64(s.Offset)
					if i == 0 {
						mm.Address = addr
					}
					mm.Strings = append(mm.Strings, fmt.Sprintf("%s@%s: %s", s.ID, hexAddr(addr), printable(s.Data)))
				}
				key := fmt.Sprintf("%s|%s|%x", m.Namespace, m.Rule, mm.Address)
				if !seen[key] {
					seen[key] = true
					res.Matches = append(res.Matches, mm)
				}
			}
			if int64(n) < size || start+uint64(size) >= r.End {
				break
			}
		}
	}
	return res, nil
}

// SuspiciousRegions returns the writable+executable private regions of pid.
func SuspiciousRegions(pid int) ([]Region, error) {
	regions, err := Regions(pid)
	if err != nil {
		return nil, err
	}
	var out []Region
	for _, r := range regions {
		if r.Suspicious() {
			out = append(out, r)
		}
	}
	return out, nil
}
