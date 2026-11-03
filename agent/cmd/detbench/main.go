// Command detbench measures the agent's file detection engines on malware
// samples and known-good files, without running anything.
//
//	detbench -samples <dir from ml/bench/fetch_malwarebazaar.py> -benign /usr/bin,/opt/app [-out report.json]
//
// Samples stay in their password-protected zips ("infected") and are only
// decrypted in memory. Every file goes through the engines the agent runs on
// files: the YARA rules (default: the built-in pack) and the static ML check
// (internal/mlscan). The known-malware hash engine is left out: the samples
// come from the same feed, so it would find them all; what matters is what
// the other engines catch of a variant no feed has seen yet.
package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/mlscan"
	"github.com/siem-platform/agent/internal/mlscore"
	"github.com/siem-platform/agent/internal/yara"
	"github.com/siem-platform/agent/internal/yarascan"
	"github.com/siem-platform/agent/internal/zipcrypto"
)

const maxFile = 64 << 20

// Sample is one manifest row (MalwareBazaar metadata).
type Sample struct {
	SHA256    string   `json:"sha256_hash"`
	FileType  string   `json:"file_type"`
	Family    string   `json:"signature"`
	FirstSeen string   `json:"first_seen"`
	Tags      []string `json:"tags"`
}

// Verdict is what the engines said about one file.
type Verdict struct {
	Path     string   `json:"path,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	FileType string   `json:"file_type,omitempty"`
	Family   string   `json:"family,omitempty"`
	YARA     []string `json:"yara,omitempty"`
	YARAHigh bool     `json:"yara_high,omitempty"` // a match of high or critical severity
	Kind     string   `json:"kind,omitempty"`      // pe, elf, or "" (the ML check does not score it)
	ML       string   `json:"ml,omitempty"`        // malicious, suspicious, clean
	MLScore  float64  `json:"ml_score,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type engines struct {
	rules *yara.Rules
	model *mlscore.Model
}

func (e engines) judge(data []byte) Verdict {
	var v Verdict
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if res, err := e.rules.Scan(ctx, data); err != nil {
		v.Error = "yara: " + err.Error()
	} else {
		for _, m := range res.Matches {
			v.YARA = append(v.YARA, m.Namespace+"/"+m.Rule)
			if s := yarascan.Severity(m.Meta); s == "high" || s == "critical" {
				v.YARAHigh = true
			}
		}
	}
	if c, ok := mlscan.Classify(e.model, data); ok {
		v.Kind, v.ML, v.MLScore = c.Kind, c.Level, c.Score
	}
	return v
}

// Tally counts detections for one group of files.
type Tally struct {
	Files        int `json:"files"`
	Scored       int `json:"scored_by_ml"` // PE or ELF
	YARAAny      int `json:"yara_any"`
	YARAHigh     int `json:"yara_high"`
	MLMalicious  int `json:"ml_malicious"`
	MLSuspicious int `json:"ml_suspicious_or_more"`
	// Detected: what raises a high alert or is blocked (YARA high/critical
	// or ML malicious). Flagged: anything that raises any alert.
	Detected int `json:"detected"`
	Flagged  int `json:"flagged"`
	Errors   int `json:"errors"`
}

func (t *Tally) add(v Verdict) {
	t.Files++
	if v.Error != "" {
		t.Errors++
	}
	if v.Kind != "" {
		t.Scored++
	}
	if len(v.YARA) > 0 {
		t.YARAAny++
	}
	if v.YARAHigh {
		t.YARAHigh++
	}
	if v.ML == "malicious" {
		t.MLMalicious++
	}
	if v.ML == "malicious" || v.ML == "suspicious" {
		t.MLSuspicious++
	}
	if v.YARAHigh || v.ML == "malicious" {
		t.Detected++
	}
	if len(v.YARA) > 0 || v.ML == "malicious" || v.ML == "suspicious" {
		t.Flagged++
	}
}

// Report is the JSON output.
type Report struct {
	Generated  time.Time         `json:"generated"`
	Rules      string            `json:"rules"`
	Model      map[string]any    `json:"model_metrics"`
	Malware    Tally             `json:"malware"`
	ByFileType map[string]*Tally `json:"malware_by_file_type"`
	ByFamily   map[string]*Tally `json:"malware_by_family"`
	Benign     Tally             `json:"benign"`
	Samples    []Verdict         `json:"samples"`
	BenignHits []Verdict         `json:"benign_flagged"`
}

func loadRules(dir string) (*yara.Rules, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yar"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no .yar files in %s", dir)
	}
	var srcs []yara.Source
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		srcs = append(srcs, yara.Source{Namespace: strings.TrimSuffix(filepath.Base(f), ".yar"), Text: string(b)})
	}
	rules, errs := yara.CompileSources(srcs)
	for _, e := range errs {
		log.Printf("rule not compiled: %v", e)
	}
	if rules == nil {
		return nil, fmt.Errorf("no rules compiled from %s", dir)
	}
	return rules, nil
}

func loadManifest(path string) (map[string]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]Sample{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var s Sample
		if json.Unmarshal(sc.Bytes(), &s) == nil && s.SHA256 != "" {
			out[strings.ToLower(s.SHA256)] = s
		}
	}
	return out, sc.Err()
}

// sampleData opens <sha>.zip and returns the entry whose SHA-256 is sha.
func sampleData(path, sha string) ([]byte, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, f := range r.File {
		b, err := zipcrypto.ReadFile(f, []byte("infected"), maxFile)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) == sha {
			return b, nil
		}
	}
	return nil, fmt.Errorf("no entry with sha256 %s", sha)
}

func main() {
	samples := flag.String("samples", "", "directory of <sha256>.zip and manifest.jsonl")
	benign := flag.String("benign", "", "comma-separated directories of known-good files")
	rulesDir := flag.String("rules", "../yara/builtin", "directory of .yar rules")
	out := flag.String("out", "", "write the JSON report here")
	flag.Parse()
	if *samples == "" && *benign == "" {
		flag.Usage()
		os.Exit(2)
	}
	rules, err := loadRules(*rulesDir)
	if err != nil {
		log.Fatal(err)
	}
	model, err := mlscore.Default()
	if err != nil {
		log.Fatal(err)
	}
	e := engines{rules: rules, model: model}
	rep := Report{Generated: time.Now().UTC(), Rules: *rulesDir, Model: model.Metrics,
		ByFileType: map[string]*Tally{}, ByFamily: map[string]*Tally{}}

	if *samples != "" {
		man, err := loadManifest(filepath.Join(*samples, "manifest.jsonl"))
		if err != nil {
			log.Fatal(err)
		}
		zips, _ := filepath.Glob(filepath.Join(*samples, "*.zip"))
		sort.Strings(zips)
		for _, z := range zips {
			sha := strings.ToLower(strings.TrimSuffix(filepath.Base(z), ".zip"))
			s := man[sha]
			data, err := sampleData(z, sha)
			var v Verdict
			if err != nil {
				v.Error = err.Error()
			} else {
				v = e.judge(data)
			}
			v.SHA256, v.FileType, v.Family = sha, s.FileType, s.Family
			rep.Samples = append(rep.Samples, v)
			rep.Malware.add(v)
			group(rep.ByFileType, orUnknown(s.FileType)).add(v)
			group(rep.ByFamily, orUnknown(s.Family)).add(v)
		}
	}
	for _, d := range strings.Split(*benign, ",") {
		if d == "" {
			continue
		}
		filepath.WalkDir(d, func(p string, de fs.DirEntry, err error) error {
			if err != nil || !de.Type().IsRegular() {
				return nil
			}
			if info, err := de.Info(); err != nil || info.Size() < 64 || info.Size() > maxFile {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			v := e.judge(data)
			if v.Kind == "" && len(v.YARA) == 0 {
				return nil // neither a program nor a YARA hit: not part of the benign set
			}
			rep.Benign.add(v)
			if len(v.YARA) > 0 || v.ML == "malicious" || v.ML == "suspicious" {
				v.Path = p
				rep.BenignHits = append(rep.BenignHits, v)
			}
			return nil
		})
	}
	printReport(rep)
	if *out != "" {
		b, _ := json.MarshalIndent(rep, "", " ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

func group(m map[string]*Tally, k string) *Tally {
	if m[k] == nil {
		m[k] = &Tally{}
	}
	return m[k]
}

func pct(n, d int) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
}

func row(name string, t *Tally) {
	fmt.Printf("%-28s %6d %8s %8s %8s %8s %9s %9s %4d\n", name, t.Files, pct(t.YARAAny, t.Files),
		pct(t.YARAHigh, t.Files), pct(t.MLMalicious, t.Scored), pct(t.MLSuspicious, t.Scored),
		pct(t.Detected, t.Files), pct(t.Flagged, t.Files), t.Errors)
}

func printReport(r Report) {
	fmt.Printf("%-28s %6s %8s %8s %8s %8s %9s %9s %4s\n", "", "files", "yara", "yara-hi", "ml-mal", "ml-susp+",
		"detected", "flagged", "err")
	if r.Malware.Files > 0 {
		row("MALWARE (all)", &r.Malware)
		types := keys(r.ByFileType, 0)
		for _, k := range types {
			row("  type "+k, r.ByFileType[k])
		}
		for _, k := range keys(r.ByFamily, 15) {
			row("  family "+trim(k, 20), r.ByFamily[k])
		}
	}
	if r.Benign.Files > 0 {
		row("BENIGN (false positives)", &r.Benign)
		for _, v := range r.BenignHits {
			fmt.Printf("  FP %s ml=%s %.3f yara=%v\n", v.Path, v.ML, v.MLScore, v.YARA)
		}
	}
	fmt.Println("ml-* columns are over the files the ML check scores (PE / ELF); detected = YARA high/critical or ML malicious; flagged = any alert")
}

// keys sorts by file count (largest first); n > 0 keeps the first n.
func keys(m map[string]*Tally, n int) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if m[ks[i]].Files != m[ks[j]].Files {
			return m[ks[i]].Files > m[ks[j]].Files
		}
		return ks[i] < ks[j]
	})
	if n > 0 && len(ks) > n {
		ks = ks[:n]
	}
	return ks
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
