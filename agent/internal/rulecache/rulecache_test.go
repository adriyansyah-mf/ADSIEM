package rulecache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type rule struct {
	Name string `json:"name"`
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "rules.json")
	if err := Save(path, "h1", []rule{{"a"}, {"b"}}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	var got []rule
	hash, err := Load(path, &got)
	if err != nil || hash != "h1" || len(got) != 2 || got[1].Name != "b" {
		t.Fatalf("hash=%q rules=%v err=%v", hash, got, err)
	}
}

func TestMissingIsErrNone(t *testing.T) {
	var got []rule
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json"), &got); !errors.Is(err, ErrNone) {
		t.Fatalf("got %v", err)
	}
}

func TestEditedFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := Save(path, "h1", []rule{{"block-evil"}}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	// someone drops the blocking rule but keeps the file valid JSON
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), "block-evil", "harmless", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	got := []rule{{"untouched"}}
	if _, err := Load(path, &got); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("an edited cache must be refused, got %v", err)
	}
	if got[0].Name != "untouched" {
		t.Fatal("rules must be left alone on a refused cache")
	}
}

func TestTruncatedFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"hash":"h1","rul`), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []rule
	if _, err := Load(path, &got); err == nil || errors.Is(err, ErrNone) {
		t.Fatalf("got %v", err)
	}
}
