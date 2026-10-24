//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func defaultStateDir() (string, error) {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "SIEMAgent"), nil
}
