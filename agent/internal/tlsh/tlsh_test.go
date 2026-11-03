package tlsh

import (
	"math/rand"
	"testing"
)

func randomText(seed int64, n int) []byte {
	rng := rand.New(rand.NewSource(seed))
	words := []string{"alpha ", "bravo ", "charlie ", "delta ", "echo ", "foxtrot ", "golf ", "hotel ", "india ",
		"juliet ", "kilo ", "lima ", "mike ", "november ", "oscar ", "papa ", "quebec ", "romeo ", "sierra "}
	var b []byte
	for len(b) < n {
		b = append(b, words[rng.Intn(len(words))]...)
	}
	return b[:n]
}

func TestStringRoundTrip(t *testing.T) {
	h, err := Sum(randomText(1, 5000))
	if err != nil {
		t.Fatal(err)
	}
	s := h.String()
	if len(s) != 72 || s[:2] != "T1" {
		t.Fatalf("digest %q", s)
	}
	p, err := Parse(s)
	if err != nil || p != h || p.String() != s {
		t.Fatalf("parse %q: %+v %v", s, p, err)
	}
	if _, err := Parse("T1XYZ"); err == nil {
		t.Error("a bad digest parsed")
	}
}

func TestSimilarAndDifferent(t *testing.T) {
	base := randomText(2, 20000)
	variant := append([]byte(nil), base...)
	copy(variant[5000:], []byte("a few changed bytes in the middle of the file"))
	other := randomText(3, 20000)
	hb, _ := Sum(base)
	hv, _ := Sum(variant)
	ho, _ := Sum(other)
	if d := Distance(hb, hb); d != 0 {
		t.Fatalf("self %d", d)
	}
	if d := Distance(hb, hv); d > 30 {
		t.Errorf("a small edit is far: %d", d)
	}
	if Distance(hb, hv) >= Distance(hb, ho) {
		t.Errorf("variant %d not closer than unrelated %d", Distance(hb, hv), Distance(hb, ho))
	}
	if Distance(hb, ho) != Distance(ho, hb) {
		t.Error("distance not symmetric")
	}
}

func TestTooShortOrUniform(t *testing.T) {
	if _, err := Sum(make([]byte, 49)); err != ErrTooSimple {
		t.Error("49 bytes hashed")
	}
	if _, err := Sum(make([]byte, 100000)); err != ErrTooSimple {
		t.Error("all zeros hashed")
	}
}

func TestTruncatedDigest(t *testing.T) {
	h, _ := Sum(randomText(4, 8000))
	full := h.String()
	cut, err := Parse(full[:len(full)-2])
	if err != nil || !cut.Truncated {
		t.Fatalf("cut digest: %+v %v", cut, err)
	}
	if d := Distance(h, cut); d != 0 {
		t.Fatalf("distance to its own cut digest %d", d)
	}
	old, err := Parse(full[2:]) // no "T1"
	if err != nil || old != h {
		t.Fatalf("digest without T1: %v", err)
	}
}

func TestLengthClasses(t *testing.T) {
	for n, want := range map[uint32]byte{50: 9, 656: 15, 657: 16, 1 << 20: 82} {
		if got := lCapturing(n); got != want {
			t.Errorf("lCapturing(%d) = %d, want %d", n, got, want)
		}
	}
}
