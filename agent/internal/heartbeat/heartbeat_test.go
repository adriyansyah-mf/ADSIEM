package heartbeat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrityHashesBinaryAndConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("server: {url: x}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ConfigPath = cfg
	defer func() { ConfigPath = "" }()

	first := currentIntegrity()
	if first == nil || len(first.BinarySHA256) != 64 || len(first.ConfigSHA256) != 64 {
		t.Fatalf("integrity %+v", first)
	}
	if err := os.WriteFile(cfg, []byte("server: {url: y}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := currentIntegrity()
	if second.ConfigSHA256 == first.ConfigSHA256 || second.BinarySHA256 != first.BinarySHA256 {
		t.Fatalf("an edited config must change only the config hash: %+v → %+v", first, second)
	}

	ConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	if in := currentIntegrity(); in.ConfigSHA256 != "" || in.BinarySHA256 == "" {
		t.Fatalf("a missing config hashes as empty: %+v", in)
	}
}
