package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestETWModeDefaultsToAutoAndRejectsTypos(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) (*Config, error) {
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte("agent:\n  state_dir: "+filepath.ToSlash(dir)+"\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	cfg, err := load("")
	if err != nil || cfg.ETW.Mode != "auto" {
		t.Fatalf("default: %+v %v", cfg, err)
	}
	for _, mode := range []string{"on", "off", "auto"} {
		if cfg, err := load("etw:\n  mode: " + mode + "\n"); err != nil || cfg.ETW.Mode != mode {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	if _, err := load("etw:\n  mode: enabled\n"); err == nil || !strings.Contains(err.Error(), "auto, on or off") {
		t.Fatalf("a typo was accepted: %v", err)
	}
}
