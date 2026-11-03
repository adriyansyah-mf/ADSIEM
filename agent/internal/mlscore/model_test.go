package mlscore

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"testing"
)

// The embedded model scores ml/train.py's sample of EMBER test vectors as
// LightGBM did when it wrote them (model.parity.json.gz).
func TestModelMatchesLightGBM(t *testing.T) {
	f, err := os.Open("model.parity.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var sample struct {
		Vectors [][]float64 `json:"vectors"`
		Scores  []float64   `json:"scores"`
	}
	if err := json.NewDecoder(r).Decode(&sample); err != nil {
		t.Fatal(err)
	}
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(sample.Vectors) == 0 || len(sample.Vectors) != len(sample.Scores) {
		t.Fatalf("%d vectors, %d scores", len(sample.Vectors), len(sample.Scores))
	}
	for i, x := range sample.Vectors {
		if got := m.Score(x); math.Abs(got-sample.Scores[i]) > 1e-6 {
			t.Errorf("vector %d: Go %.9f, LightGBM %.9f", i, got, sample.Scores[i])
		}
	}
	if !(m.Thresholds.FPR1 > 0 && m.Thresholds.FPR1 < m.Thresholds.FPR01 && m.Thresholds.FPR01 < 1) {
		t.Errorf("thresholds %+v", m.Thresholds)
	}
}
