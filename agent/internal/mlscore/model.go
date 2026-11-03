package mlscore

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"sync"
)

//go:embed model.json.gz
var embeddedModel []byte

//go:embed model_elf.json.gz
var embeddedELFModel []byte

// Model is a LightGBM binary model exported by ml/train.py (format 1, the
// EMBER 2018 vector) or ml/v3/train.py (format 2, features v3: EMBER2024).
type Model struct {
	Format     int    `json:"format"`
	Features   string `json:"features"`
	Kind       string `json:"kind"` // pe or elf (format 2)
	Dim        int    `json:"dim"`
	Trees      []tree `json:"trees"`
	Thresholds struct {
		FPR1  float64 `json:"fpr_1pct"`
		FPR01 float64 `json:"fpr_0_1pct"`
	} `json:"thresholds"`
	Metrics map[string]any `json:"metrics"`
}

// tree: node i is internal when i < len(F); a child c >= 0 is a node, c < 0
// the leaf ^c. M is the missing type (0 none, 1 zero, 2 NaN).
type tree struct {
	Root int       `json:"root"`
	F    []int     `json:"f"`
	T    []float64 `json:"t"`
	L    []int     `json:"l"`
	R    []int     `json:"r"`
	DL   []bool    `json:"dl"`
	M    []int     `json:"m"`
	V    []float64 `json:"v"`
}

func (t *tree) value(x []float64) float64 {
	n := t.Root
	if n < 0 {
		return t.V[^n]
	}
	for {
		// trained on float32 features (ml/train.py): compare what LightGBM saw
		f := float64(float32(x[t.F[n]]))
		var left bool
		switch {
		case t.M[n] == 2 && math.IsNaN(f), t.M[n] == 1 && f == 0:
			left = t.DL[n]
		default:
			left = f <= t.T[n]
		}
		next := t.R[n]
		if left {
			next = t.L[n]
		}
		if next < 0 {
			return t.V[^next]
		}
		n = next
	}
}

// Score is the probability that x (Vector's output) is malicious.
func (m *Model) Score(x []float64) float64 {
	sum := 0.0
	for i := range m.Trees {
		sum += m.Trees[i].value(x)
	}
	return 1 / (1 + math.Exp(-sum))
}

// LoadModel reads a model file as ml/train.py writes it (gzip JSON).
func LoadModel(gz []byte) (*Model, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, err
	}
	switch {
	case m.Format == 1 && m.Dim == Dim:
	case m.Format == 2 && m.Features == "v3" && m.Dim == DimV3:
	default:
		return nil, fmt.Errorf("model format %d features %q dim %d not supported", m.Format, m.Features, m.Dim)
	}
	return &m, nil
}

// ScoreFile scores a file's bytes with the features the model was trained
// on; ok is false when the file cannot be scored (format 1: not a PE the
// extractor reads).
func (m *Model) ScoreFile(b []byte) (float64, bool) {
	if m.Format == 2 {
		return m.Score(VectorV3(ExtractV3(b))), true
	}
	r, err := ExtractPE(b)
	if err != nil {
		return 0, false
	}
	return m.Score(Vector(r)), true
}

var (
	defaultOnce  sync.Once
	defaultModel *Model
	defaultErr   error
)

// Default is the embedded PE model (loaded once, on first use).
func Default() (*Model, error) {
	defaultOnce.Do(func() { defaultModel, defaultErr = LoadModel(embeddedModel) })
	return defaultModel, defaultErr
}

var (
	elfOnce  sync.Once
	elfModel *Model
	elfErr   error
)

// DefaultELF is the embedded ELF model (EMBER2024's ELF files).
func DefaultELF() (*Model, error) {
	elfOnce.Do(func() { elfModel, elfErr = LoadModel(embeddedELFModel) })
	return elfModel, elfErr
}
