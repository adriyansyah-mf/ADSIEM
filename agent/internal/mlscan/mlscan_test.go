package mlscan

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/mlscore"
)

const pe64 = "../yara/testdata/differential/fixtures/pe64.exe"

// constModel scores every file sigmoid(logit).
func constModel(t *testing.T, logit float64) *mlscore.Model {
	t.Helper()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	fmt.Fprintf(w, `{"format":1,"dim":%d,"trees":[{"root":-1,"v":[%g]}],"thresholds":{"fpr_1pct":0.5,"fpr_0_1pct":0.9}}`,
		mlscore.Dim, logit)
	w.Close()
	m, err := mlscore.LoadModel(gz.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readPE(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(pe64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var miner = append([]byte("\x7fELF"+strings.Repeat("\x00", 60)), []byte("stratum+tcp://pool xmrig")...)

func TestClassifyLevels(t *testing.T) {
	pe := readPE(t)
	for _, c := range []struct {
		logit float64
		level string
	}{{4, "malicious"}, {0.5, "suspicious"}, {-4, "clean"}} {
		v, ok := Classify(constModel(t, c.logit), nil, pe)
		if !ok || v.Kind != "pe" || v.Engine != "ember_lgbm" || v.Level != c.level {
			t.Errorf("logit %v: %+v ok=%v, want level %s", c.logit, v, ok, c.level)
		}
	}
	v, ok := Classify(constModel(t, -4), nil, miner)
	if !ok || v.Kind != "elf" || v.Level != "malicious" || len(v.Reasons) < 2 {
		t.Errorf("miner ELF: %+v ok=%v", v, ok)
	}
	if _, ok := Classify(constModel(t, 4), nil, []byte("#!/bin/sh\necho hi\n")); ok {
		t.Error("a shell script was scored")
	}
	if _, ok := Classify(constModel(t, 4), nil, append([]byte("MZ"), make([]byte, 200)...)); ok {
		t.Error("a broken PE was scored")
	}
}

// With the embedded EMBER2024 models: a PE the parser refuses is still
// scored (byte and string features), and ELF files go to the ELF model.
func TestEmbeddedModels(t *testing.T) {
	pe, err := mlscore.Default()
	if err != nil {
		t.Fatal(err)
	}
	elf, err := mlscore.DefaultELF()
	if err != nil {
		t.Fatal(err)
	}
	if pe.Format != 2 || pe.Kind != "pe" || elf.Kind != "elf" {
		t.Fatalf("models: pe format %d kind %q, elf kind %q", pe.Format, pe.Kind, elf.Kind)
	}
	broken := append([]byte("MZ"), make([]byte, 4000)...)
	if v, ok := Classify(pe, elf, broken); !ok || v.Kind != "pe" || v.Engine != "ember2024_lgbm" {
		t.Fatalf("broken PE: %+v %v", v, ok)
	}
	if b, err := os.ReadFile("/bin/true"); err == nil {
		v, ok := Classify(pe, elf, b)
		if !ok || v.Kind != "elf" || v.Level != "clean" {
			t.Fatalf("/bin/true: %+v %v", v, ok)
		}
	}
	if v, ok := Classify(pe, elf, readPE(t)); !ok || v.Engine != "ember2024_lgbm" {
		t.Fatalf("pe64 fixture: %+v %v", v, ok)
	}
}

type pushed struct{ lines []string }

func (p *pushed) push(logType, line string) {
	if logType != LogType {
		panic(logType)
	}
	p.lines = append(p.lines, line)
}

func TestCheckerModes(t *testing.T) {
	pe := readPE(t)
	for _, c := range []struct {
		name, mode string
		logit      float64
		known      bool
		quarantine error
		wantLine   string // "" no line
		wantQ      bool
	}{
		{"detect", "", 4, false, nil, "action=detected level=malicious kind=pe", false},
		{"block", ModeBlock, 4, false, nil, "action=quarantined level=malicious", true},
		{"block fails", ModeBlock, 4, false, errors.New("in use"), `action=detected level=malicious kind=pe engine=ember_lgbm score=0.9820 threshold=0.9000 sha256=abc path="C:\\d.exe" size=`, true},
		{"block suspicious", ModeBlock, 0.5, false, nil, "action=detected level=suspicious", false},
		{"off", ModeOff, 4, false, nil, "", false},
		{"known malware", ModeBlock, 4, true, nil, "", false},
		{"clean", ModeBlock, -4, false, nil, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var p pushed
			var q []string
			ch := &Checker{Model: constModel(t, c.logit), Push: p.push,
				Quarantine: func(path string) error { q = append(q, path); return c.quarantine },
				Mode:       func(string, string) string { return c.mode },
				Known:      func(string) bool { return c.known }}
			ch.Check(`C:\d.exe`, "abc", pe, "")
			if c.wantLine == "" {
				if len(p.lines) != 0 {
					t.Fatalf("lines %q", p.lines)
				}
			} else if len(p.lines) != 1 || !strings.Contains(p.lines[0], c.wantLine) {
				t.Fatalf("lines %q, want ...%s...", p.lines, c.wantLine)
			}
			if (len(q) == 1) != c.wantQ {
				t.Fatalf("quarantined %q, want %v", q, c.wantQ)
			}
			if c.quarantine != nil && !strings.Contains(p.lines[0], `error="in use"`) {
				t.Fatalf("no error in %q", p.lines[0])
			}
		})
	}
}

func TestCheckerReportsOnce(t *testing.T) {
	var p pushed
	ch := &Checker{Model: constModel(t, -4), Push: p.push}
	ch.Check("/tmp/m", "s1", miner, "")
	ch.Check("/tmp/m", "s1", miner, "")
	ch.Check("/tmp/m", "s2", miner, "")
	if len(p.lines) != 2 || !strings.Contains(p.lines[0], `reasons="`) {
		t.Fatalf("lines %q", p.lines)
	}
}
