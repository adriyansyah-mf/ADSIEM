package mlscan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/mlscore"
)

// TestSurvey scores every PE and ELF file under MLSCAN_DIRS (comma
// separated) with the embedded model and logs how many reach each level,
// with the flagged files: a false-positive check on known-good software.
func TestSurvey(t *testing.T) {
	dirs := os.Getenv("MLSCAN_DIRS")
	if dirs == "" {
		t.Skip("set MLSCAN_DIRS")
	}
	m, err := mlscore.Default()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, d := range strings.Split(dirs, ",") {
		filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return nil
			}
			if info, err := e.Info(); err != nil || info.Size() > 32<<20 || info.Size() < 64 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			v, ok := Classify(m, b)
			if !ok {
				return nil
			}
			counts[v.Kind+" "+v.Level]++
			if v.Level != "clean" {
				t.Logf("%s %s %.4f %s %v", v.Kind, v.Level, v.Score, p, v.Reasons)
			}
			return nil
		})
	}
	t.Logf("counts %v", counts)
}
