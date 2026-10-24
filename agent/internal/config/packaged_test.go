package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The packaged templates document evidence settings as comments; once an
// operator uncomments them they must load as intended.
func TestPackagedEvidenceExamplesLoadWhenUncommented(t *testing.T) {
	uncomment := regexp.MustCompile(`(?m)^# (evidence:|  enabled:|  dir:|  max_bytes:)`)
	for _, template := range []string{"../../packaging/config.yaml", "../../packaging/windows/config.yaml"} {
		t.Run(template, func(t *testing.T) {
			b, err := os.ReadFile(template)
			if err != nil {
				t.Fatal(err)
			}
			state := t.TempDir()
			body := uncomment.ReplaceAll(b, []byte("$1"))
			body = regexp.MustCompile(`(?m)^agent:\n`).ReplaceAll(body, []byte("agent:\n  state_dir: "+quote(state)+"\n"))
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("uncommented example does not load: %v", err)
			}
			want, _ := filepath.EvalSymlinks(state)
			if !cfg.Evidence.Enabled || cfg.Evidence.MaxBytes != 1<<30 || cfg.Evidence.Dir != filepath.Join(want, "evidence") {
				t.Fatalf("evidence %+v", cfg.Evidence)
			}
		})
	}
}

func quote(s string) string { return `"` + regexp.MustCompile(`\\`).ReplaceAllString(s, `\\`) + `"` }
