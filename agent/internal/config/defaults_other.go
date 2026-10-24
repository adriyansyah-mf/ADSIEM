//go:build !linux && !windows

package config

import (
	"os"
	"path/filepath"
)

func defaultStateDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "siem-agent"), nil
}
