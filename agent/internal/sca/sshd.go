package sca

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sshdConfigPath/sshdConfigDir are fixed rather than policy-configurable —
// unlike everything else in this package they aren't expressed as a DSL
// rule because sshd's own Include-resolution semantics (first occurrence
// wins, recursing into globbed drop-in files) can't be expressed as a
// single regex/file rule. The sshd: selector in rules.go is a thin wrapper
// around this resolved view.
const (
	sshdConfigPath = "/etc/ssh/sshd_config"
	sshdConfigDir  = "/etc/ssh"
)

// loadSSHDConfig resolves the same effective directive map a real sshd
// process would compute from sshdConfigPath, Include directives and all.
func loadSSHDConfig() (map[string]string, error) {
	return loadSSHDConfigFrom(sshdConfigPath)
}

func loadSSHDConfigFrom(path string) (map[string]string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	result := make(map[string]string)
	parseSSHDConfigInto(path, result)
	return result, nil
}

// parseSSHDConfigInto opens path and merges its directives into result,
// expanding any Include directive inline (recursively) at the point it
// appears — matching sshd's own top-to-bottom, first-occurrence-wins
// processing, whether the directive comes from the main file or one it
// includes. Errors opening an included file are ignored, same as sshd's own
// leniency about optional Include globs.
func parseSSHDConfigInto(path string, result map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "include" {
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(sshdConfigDir, pattern)
				}
				matches, err := filepath.Glob(pattern)
				if err != nil {
					continue
				}
				sort.Strings(matches)
				for _, m := range matches {
					parseSSHDConfigInto(m, result)
				}
			}
			continue
		}
		if _, exists := result[key]; !exists {
			result[key] = fields[1]
		}
	}
}
