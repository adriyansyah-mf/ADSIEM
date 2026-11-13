package mlscan

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/mlscore"
)

// elfModel is an ELF model (format 2) scoring every file p, with the
// embedded model's thresholds.
func elfModel(t *testing.T, p float64) *mlscore.Model {
	t.Helper()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	fmt.Fprintf(w, `{"format":2,"features":"v3","kind":"elf","dim":%d,"trees":[{"root":-1,"v":[%g]}],"thresholds":{"fpr_1pct":0.99697,"fpr_0_1pct":0.99998}}`,
		mlscore.DimV3, math.Log(p/(1-p)))
	w.Close()
	m, err := mlscore.LoadModel(gz.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The miner dropped on otakunesia: model 0.98, under the model's own
// thresholds, so "clean" anywhere but a temp directory.
func TestELFInTempDirectoryHeldToStricterThresholds(t *testing.T) {
	plain := []byte("\x7fELF" + strings.Repeat("\x00", 200))
	for _, c := range []struct {
		score       float64
		path, level string
	}{
		{0.98, "/var/tmp/systemd-private-x-apache2.service-y/tmp/.7625e6d2e", "malicious"},
		{0.98, "/dev/shm/.x", "malicious"},
		{0.98, "/tmp/kdevtmpfsi", "malicious"},
		{0.92, "/tmp/x", "suspicious"},
		{0.82, "/tmp/go-build123/b001/mountns.test", "clean"},
		{0.98, "/usr/bin/ntlm_brute", "clean"},
		{0.98, "/opt/tmp/x", "clean"},
		{0.98, "", "clean"},
	} {
		v, ok := ClassifyAt(nil, elfModel(t, c.score), plain, c.path)
		if !ok || v.Level != c.level {
			t.Errorf("%.2f at %q: %+v, want %s", c.score, c.path, v, c.level)
			continue
		}
		staged := len(v.Reasons) > 0 && v.Reasons[len(v.Reasons)-1] == "ELF in a temp directory"
		if staged != (c.level != "clean") {
			t.Errorf("%q: reasons %q", c.path, v.Reasons)
		}
	}
	// the heuristics keep a higher verdict
	v, _ := ClassifyAt(nil, elfModel(t, 0.5), miner, "/tmp/m")
	if v.Level != "malicious" || v.Engine != "elf_heuristic" {
		t.Errorf("heuristic verdict lost: %+v", v)
	}
}

// Checker passes the path: block mode quarantines the temp-dir miner.
func TestCheckQuarantinesELFInTempDirectory(t *testing.T) {
	var p pushed
	var quarantined []string
	c := &Checker{ELF: elfModel(t, 0.98), Push: p.push,
		Mode:       func(string, string) string { return ModeBlock },
		Quarantine: func(path string) error { quarantined = append(quarantined, path); return nil }}
	plain := []byte("\x7fELF" + strings.Repeat("\x00", 200))
	c.Check("/usr/local/bin/tool", "aa", plain, "on_access")
	c.Check("/var/tmp/.7625e6d2e", "bb", plain, "on_access")
	if len(quarantined) != 1 || quarantined[0] != "/var/tmp/.7625e6d2e" || len(p.lines) != 1 ||
		!strings.Contains(p.lines[0], "action=quarantined level=malicious") {
		t.Fatalf("quarantined %q, lines %q", quarantined, p.lines)
	}
}

// With the embedded model and the real sample, when it is at hand
// (MINER_SAMPLE; the incident's sha256 be6e1b6c...16dd is not in the repo).
func TestEmbeddedModelOnIncidentSample(t *testing.T) {
	path := os.Getenv("MINER_SAMPLE")
	if path == "" {
		t.Skip("MINER_SAMPLE not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	elf, err := mlscore.DefaultELF()
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := Classify(nil, elf, b); v.Level != "clean" {
		t.Logf("outside a temp directory: %+v", v)
	}
	if v, _ := ClassifyAt(nil, elf, b, "/var/tmp/.7625e6d2e"); v.Level != "malicious" {
		t.Fatalf("in /var/tmp: %+v", v)
	}
}
