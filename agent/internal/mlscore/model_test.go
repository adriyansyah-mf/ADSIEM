package mlscore

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"testing"
)

// The embedded models score the training script's sample of test vectors
// as LightGBM did when it wrote them (*.parity.json.gz).
func checkParity(t *testing.T, m *Model, file string) {
	t.Helper()
	f, err := os.Open(file)
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
	if len(sample.Vectors) == 0 || len(sample.Vectors) != len(sample.Scores) {
		t.Fatalf("%d vectors, %d scores", len(sample.Vectors), len(sample.Scores))
	}
	for i, x := range sample.Vectors {
		if got := m.Score(x); math.Abs(got-sample.Scores[i]) > 1e-6 {
			t.Errorf("%s vector %d: Go %.9f, LightGBM %.9f", file, i, got, sample.Scores[i])
		}
	}
	if !(m.Thresholds.FPR1 > 0 && m.Thresholds.FPR1 < m.Thresholds.FPR01 && m.Thresholds.FPR01 < 1) {
		t.Errorf("%s thresholds %+v", file, m.Thresholds)
	}
}

func TestModelMatchesLightGBM(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	checkParity(t, m, "model.parity.json.gz")
}

func TestELFModelMatchesLightGBM(t *testing.T) {
	m, err := DefaultELF()
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != 2 || m.Kind != "elf" {
		t.Fatalf("ELF model format %d kind %q", m.Format, m.Kind)
	}
	checkParity(t, m, "model_elf.parity.json.gz")
}
