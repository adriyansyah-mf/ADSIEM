package mlscore

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestDumpV3 writes the raw v3 features of every file listed (one path per
// line) in MLSCORE_V3_LIST as JSON lines to MLSCORE_V3_OUT, for
// ml/v3/compare.py to check against ml/v3/reference.py.
func TestDumpV3(t *testing.T) {
	list, outPath := os.Getenv("MLSCORE_V3_LIST"), os.Getenv("MLSCORE_V3_OUT")
	if list == "" || outPath == "" {
		t.Skip("set MLSCORE_V3_LIST and MLSCORE_V3_OUT")
	}
	in, err := os.Open(list)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		path := strings.TrimSpace(sc.Text())
		b, err := os.ReadFile(path)
		if err != nil || len(b) == 0 {
			continue
		}
		raw := ExtractV3(b)
		line, _ := json.Marshal(map[string]any{"file": path, "raw": raw, "vector": VectorV3(raw)})
		w.Write(append(line, '\n'))
	}
}
