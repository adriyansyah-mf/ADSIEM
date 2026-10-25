package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func evidenceConfigFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEvidenceConfigDefaults(t *testing.T) {
	// Given / When
	cfg, err := Load(evidenceConfigFile(t, "{}"))
	if err != nil {
		t.Fatal(err)
	}
	// Then
	wantState := "/var/lib/siem-agent"
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		wantState = filepath.Join(base, "SIEMAgent")
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		base, e := os.UserConfigDir()
		if e != nil {
			t.Fatal(e)
		}
		wantState = filepath.Join(base, "siem-agent")
	}
	if cfg.Agent.StateDir != wantState || cfg.Evidence.Dir != filepath.Join(wantState, "evidence") {
		t.Fatalf("unexpected paths: %+v", cfg)
	}
	if cfg.Evidence.Enabled || cfg.Evidence.MaxBytes != 1<<30 || cfg.Evidence.SegmentBytes != 16<<20 || cfg.Evidence.MaxEventBytes != 1<<20 || cfg.Evidence.ReservedBytes != 16<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg.Evidence)
	}
}

func TestEvidenceConfigCustomState(t *testing.T) {
	// Given
	state := t.TempDir()
	// When
	cfg, err := Load(evidenceConfigFile(t, fmt.Sprintf("agent:\n  state_dir: %q\n", state)))
	if err != nil {
		t.Fatal(err)
	}
	// Then: Load canonicalizes the state directory (on Windows that also
	// expands 8.3 short names such as RUNNER~1)
	if state, err = filepath.EvalSymlinks(state); err != nil {
		t.Fatal(err)
	}
	if cfg.Evidence.Dir != filepath.Join(state, "evidence") || cfg.Buffer.SpillPath != filepath.Join(state, "spill.log") || cfg.Firewall.StatePath != filepath.Join(state, "firewall.json") {
		t.Fatalf("state paths not derived: %+v", cfg)
	}
}

func TestEvidenceConfigRejectsInvalid(t *testing.T) {
	state := t.TempDir()
	for _, body := range []string{
		"evidence:\n  max_bytes: -1\n", "evidence:\n  segment_bytes: -1\n", "evidence:\n  reserved_bytes: -1\n", "evidence:\n  max_event_bytes: -1\n",
		"evidence:\n  max_bytes: 100\n  reserved_bytes: 20\n  segment_bytes: 90\n  max_event_bytes: 1\n",
		"agent:\n  id: invalid\n",
		fmt.Sprintf("agent:\n  state_dir: %q\nevidence:\n  dir: %q\n", state, filepath.Join(state, "..", "outside")),
		fmt.Sprintf("agent:\n  state_dir: %q\nevidence:\n  dir: %q\n", state, state),
	} {
		t.Run(body, func(t *testing.T) {
			// When / Then
			if _, err := Load(evidenceConfigFile(t, body)); err == nil {
				t.Fatalf("accepted invalid config %q", body)
			}
		})
	}
}

func TestEvidenceConfigRejectsSymlinkEscape(t *testing.T) {
	// Given
	state, outside := t.TempDir(), t.TempDir()
	link := filepath.Join(state, "escape")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		if output, junctionErr := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); junctionErr != nil {
			t.Fatalf("create junction: %v (%s); symlink error: %v", junctionErr, output, err)
		}
	}
	// When
	_, err := Load(evidenceConfigFile(t, fmt.Sprintf("agent:\n  state_dir: %q\nevidence:\n  dir: %q\n", state, filepath.Join(link, "new", "journal"))))
	// Then
	if err == nil {
		t.Fatal("accepted symlink escape through existing ancestor")
	}
}

func TestEvidenceConfigRejectsFileDirectory(t *testing.T) {
	// Given
	state := t.TempDir()
	file := filepath.Join(state, "journal")
	if err := os.WriteFile(file, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	// When
	_, err := Load(evidenceConfigFile(t, fmt.Sprintf("agent:\n  state_dir: %q\nevidence:\n  dir: %q\n", state, file)))
	// Then
	if err == nil {
		t.Fatal("accepted regular file as evidence directory")
	}
}

func TestEvidenceConfigLoadDoesNotCreateState(t *testing.T) {
	// Given
	state := filepath.Join(t.TempDir(), "missing", "state")
	// When
	_, err := Load(evidenceConfigFile(t, fmt.Sprintf("agent:\n  state_dir: %q\n", state)))
	if err != nil {
		t.Fatal(err)
	}
	// Then
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("Load created state or unexpected stat error: %v", err)
	}
}

func TestEvidenceConfigResolvedStateSurvivesSave(t *testing.T) {
	// Given: Windows uses a junction when unprivileged symlinks are unavailable.
	actual := t.TempDir()
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(actual, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, actual).CombinedOutput(); err != nil {
			t.Fatalf("create junction: %v (%s)", err, output)
		}
	}
	path := evidenceConfigFile(t, fmt.Sprintf("agent:\n  state_dir: %q\n", link))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	// When
	_, err = Load(path)
	// Then
	if err != nil {
		t.Fatalf("saved resolved paths cannot reload: %v", err)
	}
}
