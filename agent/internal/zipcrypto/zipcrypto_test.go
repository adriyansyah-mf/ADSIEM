package zipcrypto

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// testdata/*.zip hold sample.txt (text, 72000 bytes) as Info-ZIP wrote it:
// `zip -P infected` (deflated), `zip -0 -P infected` (stored), `zip` (plain).
const sampleSHA = "7ba32e4d4a5b440c6f8693b22d78e792ef0deed9ddb15d26238fcd6ac19872f1"

func entry(t *testing.T, name string) *zip.File {
	t.Helper()
	r, err := zip.OpenReader("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if len(r.File) != 1 {
		t.Fatalf("%s: %d entries", name, len(r.File))
	}
	return r.File[0]
}

func TestReadFile(t *testing.T) {
	for _, name := range []string{"deflate.zip", "store.zip", "plain.zip"} {
		b, err := ReadFile(entry(t, name), []byte("infected"), 1<<20)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != sampleSHA {
			t.Errorf("%s: sha256 %s", name, got)
		}
	}
}

func TestWrongPasswordAndLimit(t *testing.T) {
	if _, err := ReadFile(entry(t, "deflate.zip"), []byte("wrong"), 1<<20); !errors.Is(err, ErrPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := ReadFile(entry(t, "store.zip"), []byte("infected"), 1000); err == nil {
		t.Error("an entry over the limit was read")
	}
}
