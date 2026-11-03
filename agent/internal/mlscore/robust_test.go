package mlscore

import (
	"math/rand"
	"os"
	"testing"
)

var robustFixtures = []string{
	"../yara/testdata/differential/fixtures/pe64.exe",
	"../yara/testdata/differential/fixtures/dll32.dll",
}

// Malware ships truncated and corrupted headers on purpose: extraction must
// return an error or features, never panic.
func TestExtractPEDoesNotPanicOnBrokenFiles(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, f := range robustFixtures {
		orig, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		try := func(what string, b []byte) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s %s: panic %v", f, what, r)
				}
			}()
			if r, err := ExtractPE(b); err == nil {
				Vector(r)
			}
		}
		for n := 0; n < len(orig); n += 1 + n/16 {
			try("truncated", orig[:n])
		}
		head := min(len(orig), 4096)
		for i := 0; i < 3000; i++ {
			b := append([]byte(nil), orig...)
			for k := 0; k < 1+rng.Intn(8); k++ {
				b[rng.Intn(head)] = byte(rng.Intn(256))
			}
			try("corrupted", b)
		}
	}
}

// The dynamic loader names the preload file and LD_PRELOAD: not suspicious.
func TestDynamicLoaderIsClean(t *testing.T) {
	b, err := os.ReadFile("/lib64/ld-linux-x86-64.so.2")
	if err != nil {
		t.Skip("no x86-64 loader here")
	}
	if s, r, ok := ScoreELF(b); !ok || s >= 0.45 {
		t.Fatalf("loader scored %.2f %v", s, r)
	}
}

func TestScoreELFDoesNotPanicOnBrokenFiles(t *testing.T) {
	orig, err := os.ReadFile("/bin/true")
	if err != nil || len(orig) < 4096 {
		t.Skip("no ELF /bin/true here")
	}
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 2000; i++ {
		b := append([]byte(nil), orig...)
		if i%2 == 0 {
			b = b[:rng.Intn(len(b))]
		}
		for k := 0; k < 1+rng.Intn(8) && len(b) > 64; k++ {
			b[4+rng.Intn(min(len(b), 4096)-4)] = byte(rng.Intn(256))
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: panic %v", i, r)
				}
			}()
			ScoreELF(b)
		}()
	}
}
