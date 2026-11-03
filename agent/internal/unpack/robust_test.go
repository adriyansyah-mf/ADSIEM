package unpack

import (
	"encoding/base64"
	"math/rand"
	"os"
	"testing"
)

// Containers come from attackers: truncated and corrupted ones must give
// items or notes, never a panic. Every parser gets mutated real input.
func TestBrokenContainersDoNotPanic(t *testing.T) {
	iso, err := os.ReadFile("testdata/small.iso.gz")
	if err != nil {
		t.Fatal(err)
	}
	isoRaw := Open(iso, DefaultLimits).Items[0].Data // the uncompressed image
	seeds := map[string][]byte{
		"zip":  zipOf(t, map[string][]byte{"a.exe": fakeExe, "b.zip": zipOf(t, map[string][]byte{"c": fakeExe})}),
		"iso":  isoRaw,
		"gz":   iso,
		"lnk":  lnkFile(`..\cmd.exe`, `C:\`, `/c calc`),
		"html": []byte(`<html><script>"` + base64.StdEncoding.EncodeToString(append([]byte("MZ"), make([]byte, 2000)...)) + `x"</script>`),
	}
	rng := rand.New(rand.NewSource(3))
	for name, seed := range seeds {
		for i := 0; i < 1500; i++ {
			b := append([]byte(nil), seed...)
			if i%3 == 0 {
				b = b[:rng.Intn(len(b)+1)]
			}
			for k := 0; k < 1+rng.Intn(10) && len(b) > 0; k++ {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s case %d: panic %v", name, i, r)
					}
				}()
				Open(b, DefaultLimits)
			}()
		}
	}
}
