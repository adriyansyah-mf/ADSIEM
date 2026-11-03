package mlscore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDumpForParity writes, for every file in MLSCORE_FILES (comma
// separated), the raw features and vector as JSON into MLSCORE_DUMP, for
// ml/compare.py to check against EMBER's own extractor and vectorize.py.
func TestDumpForParity(t *testing.T) {
	dir, files := os.Getenv("MLSCORE_DUMP"), os.Getenv("MLSCORE_FILES")
	if dir == "" || files == "" {
		t.Skip("set MLSCORE_DUMP and MLSCORE_FILES")
	}
	for _, f := range strings.Split(files, ",") {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ExtractPE(b)
		if err != nil {
			t.Logf("%s: %v", f, err)
			continue
		}
		out, _ := json.Marshal(map[string]any{"file": f, "raw": r.EMBER(), "vector": Vector(r)})
		name := filepath.Join(dir, strings.ReplaceAll(strings.TrimPrefix(f, "/"), "/", "_")+".json")
		if err := os.WriteFile(name, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
