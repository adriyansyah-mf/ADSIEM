package tlsh

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestSurveyPairs hashes the programs (ELF, PE) under TLSH_DIRS and reports
// how many pairs of different programs are within a distance, to choose a
// variant threshold that unrelated software does not reach.
func TestSurveyPairs(t *testing.T) {
	dirs := os.Getenv("TLSH_DIRS")
	if dirs == "" {
		t.Skip("set TLSH_DIRS")
	}
	type item struct {
		path string
		h    Hash
	}
	var items []item
	seen := map[string]bool{}
	for _, d := range strings.Split(dirs, ",") {
		filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() || len(items) >= 4000 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || len(b) < 4096 || len(b) > 64<<20 {
				return nil
			}
			if !bytes.HasPrefix(b, []byte("\x7fELF")) && !bytes.HasPrefix(b, []byte("MZ")) {
				return nil
			}
			h, err := Sum(b)
			if err != nil || seen[h.String()] {
				return nil
			}
			seen[h.String()] = true
			items = append(items, item{p, h})
			return nil
		})
	}
	counts := map[int]int{}
	var close []string
	for i := range items {
		for j := i + 1; j < len(items); j++ {
			d := Distance(items[i].h, items[j].h)
			for _, th := range []int{10, 20, 30, 40, 50} {
				if d <= th {
					counts[th]++
				}
			}
			if d <= 30 && len(close) < 40 {
				close = append(close, filepath.Base(items[i].path)+" ~ "+filepath.Base(items[j].path))
			}
		}
	}
	n := len(items)
	t.Logf("%d programs, %d pairs", n, n*(n-1)/2)
	ths := []int{10, 20, 30, 40, 50}
	sort.Ints(ths)
	for _, th := range ths {
		t.Logf("pairs within %d: %d", th, counts[th])
	}
	for _, c := range close {
		t.Logf("  %s", c)
	}
}
