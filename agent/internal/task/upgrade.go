// agent/internal/task/upgrade.go
package task

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func upgradeAgent(serverURL, downloadURL string) (any, error) {
	fullURL := serverURL + downloadURL

	resp, err := http.Get(fullURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "siem-agent-upgrade-*")
	if err != nil {
		return nil, fmt.Errorf("tempfile: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("write binary: %w", err)
	}
	tmp.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("chmod: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		exePath = "/usr/bin/siem-agent"
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("replace binary: %w", err)
	}

	// Restart after result submission has time to complete
	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("systemctl", "restart", "siem-agent").Run() //nolint:errcheck
	}()

	return map[string]any{"replaced": true, "path": exePath, "restarting": true}, nil
}
