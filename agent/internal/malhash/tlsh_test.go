package malhash

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siem-platform/agent/internal/tlsh"
)

func sample(seed int64, n int) []byte {
	rng := rand.New(rand.NewSource(seed))
	words := []string{"connect ", "beacon ", "upload ", "steal ", "cookies ", "wallet ", "discord ", "token ",
		"chrome ", "login ", "data ", "socket ", "inject ", "process ", "registry ", "persist "}
	var b []byte
	for len(b) < n {
		b = append(b, words[rng.Intn(len(words))]...)
	}
	return b[:n]
}

// noise: content unlike sample's (another byte distribution)
func noise(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func digest(t *testing.T, b []byte) string {
	t.Helper()
	h, err := tlsh.Sum(b)
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

func TestSimilarFindsTheNearestWithinTheDistance(t *testing.T) {
	known, other := sample(1, 30000), sample(2, 30000)
	s := NewWithTLSH(ActionDetect, [][]string{
		{shaOf(known), "Lumma", digest(t, known)},
		{shaOf(other), "Vidar", digest(t, other)},
		{sha("9"), "NoDigest"},
		{sha("8"), "BadDigest", "T1XYZ"},
	})
	if s.Len() != 4 || s.SimilarCount() != 2 {
		t.Fatalf("len %d similar %d", s.Len(), s.SimilarCount())
	}
	variant := append([]byte(nil), known...)
	copy(variant[12000:], "a recompiled build with a different config block")
	h, _ := tlsh.Sum(variant)
	label, similar, dist, ok := s.Similar(h, VariantDistance)
	if !ok || label != "Lumma" || similar != shaOf(known) || dist > VariantDistance {
		t.Fatalf("variant: %q %s %d %v", label, similar, dist, ok)
	}
	unrelated, _ := tlsh.Sum(noise(3, 30000))
	if _, _, d, ok := s.Similar(unrelated, VariantDistance); ok {
		t.Fatalf("unrelated content matched at %d", d)
	}
	// a delta keeps the digests of the hashes it does not touch
	s2 := s.apply(false, [][]string{{sha("7"), "New"}})
	if s2.SimilarCount() != 2 {
		t.Fatalf("digests lost on a delta: %d", s2.SimilarCount())
	}
}

func TestSavedDigestsAndTheResyncOfOldSets(t *testing.T) {
	known := sample(4, 20000)
	path := filepath.Join(t.TempDir(), FileName)
	s := NewWithTLSH(ActionDetect, [][]string{{shaOf(known), "Lumma", digest(t, known)}, {sha("1"), "x"}})
	s.Seq, s.Version = 7, "7:detect"
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.SimilarCount() != 1 || got.Seq != 7 || got.Version != "7:detect" {
		t.Fatalf("load: %+v %v", got, err)
	}
	// a file from an agent before TLSH: still enforced, synced again in full
	old := onDisk{Format: format, Seq: 9, Action: ActionDetect, Version: "9:detect", Labels: []uint16{0}, Table: []string{"x"},
		Keys: make([]byte, 32)}
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(old)
	os.WriteFile(path, buf.Bytes(), 0o600)
	got, err = Load(path)
	if err != nil || got.Len() != 1 || got.Seq != 0 || got.Version != "" {
		t.Fatalf("old set: %+v %v", got, err)
	}
}

func TestFileCheckerReportsVariants(t *testing.T) {
	known := sample(5, 30000)
	st := Open(filepath.Join(t.TempDir(), FileName))
	var lines []string
	fc := &FileChecker{Store: st, Push: func(_, l string) { lines = append(lines, l) },
		Quarantine: func(string) error { t.Fatal("a variant is never quarantined"); return nil }}
	st.cur.Store(NewWithTLSH(ActionBlock, [][]string{{shaOf(known), "Lumma", digest(t, known)}}))

	variant := append([]byte(nil), known...)
	copy(variant[100:], "patched")
	fc.CheckData("/tmp/v.exe", shaOf(variant), variant, "")
	fc.CheckData("/tmp/v.exe", shaOf(variant), variant, "")                 // once a minute
	fc.CheckData("/tmp/k.exe", shaOf(known), known, "")                     // the known file itself: Check's job
	fc.CheckData("/tmp/o.exe", shaOf(noise(6, 30000)), noise(6, 30000), "") // unrelated
	fc.CheckData("/tmp/s.exe", shaOf(variant[:100]), variant[:100], "")     // too small
	if len(lines) != 1 {
		t.Fatalf("lines %v", lines)
	}
	for _, want := range []string{`action=detected`, `label="Lumma"`, `path="/tmp/v.exe"`, `match=tlsh`,
		`similar_to=` + shaOf(known), `distance=`} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("missing %s in %s", want, lines[0])
		}
	}
}
