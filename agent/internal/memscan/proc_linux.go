//go:build linux

package memscan

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Regions parses /proc/<pid>/maps.
func Regions(pid int) ([]Region, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Region
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		// start-end perms offset dev inode [path]
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		r := Region{Start: start, End: end, Perms: fields[1][:3], Kind: "anon"}
		if len(fields) >= 6 {
			r.Path = strings.Join(fields[5:], " ")
			switch {
			case r.Path == "[heap]":
				r.Kind = "heap"
			case strings.HasPrefix(r.Path, "[stack"):
				r.Kind = "stack"
			case r.Path == "[vvar]" || r.Path == "[vsyscall]" || r.Path == "[vdso]" || r.Path == "[vvar_vclock]":
				r.Kind = "kernel" // reading these fails or is meaningless
				r.Perms = "---"
			case strings.HasPrefix(r.Path, "/memfd:") || strings.HasSuffix(r.Path, " (deleted)"):
				r.Kind = "anon" // no file on disk to compare with
			case strings.HasPrefix(r.Path, "/"):
				r.Kind = "file"
			}
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

type procMem struct{ f *os.File }

func (m procMem) ReadAt(p []byte, addr uint64) (int, error) { return m.f.ReadAt(p, int64(addr)) }
func (m procMem) Close() error                              { return m.f.Close() }

// Reader reads another process's memory.
type Reader interface {
	ReadAt(p []byte, addr uint64) (int, error)
	Close() error
}

// Open opens /proc/<pid>/mem (needs ptrace access: root, or the same user
// with ptrace_scope 0).
func Open(pid int) (Reader, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	return procMem{f}, nil
}

// ProcessImage is the executable of pid, or its name when that is gone.
func ProcessImage(pid int) string {
	if p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		return p
	}
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(b))
}

// Processes lists user-space processes (kernel threads have no maps).
func Processes() ([]Proc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []Proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || exe == "" {
			continue
		}
		out = append(out, Proc{PID: pid, Image: exe})
	}
	return out, nil
}
