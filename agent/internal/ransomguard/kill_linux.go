//go:build linux

package ransomguard

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// children maps a pid to its children, from /proc/<pid>/stat.
func children() map[int][]int {
	out := map[int][]int{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...; comm may contain spaces and parens.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		out[ppid] = append(out[ppid], pid)
	}
	return out
}

// killTree stops pid and its descendants first (so none of them keeps
// encrypting or forks away while we look), then kills them all.
func killTree(pid uint32) (int, error) {
	root := int(pid)
	if err := syscall.Kill(root, syscall.SIGSTOP); err != nil {
		return 0, err
	}
	tree := []int{root}
	kids := children()
	self := os.Getpid()
	for i := 0; i < len(tree) && len(tree) < 4096; i++ {
		for _, c := range kids[tree[i]] {
			if c != self {
				syscall.Kill(c, syscall.SIGSTOP)
				tree = append(tree, c)
			}
		}
	}
	killed := 0
	for _, p := range tree {
		if syscall.Kill(p, syscall.SIGKILL) == nil {
			killed++
		}
	}
	return killed, nil
}
