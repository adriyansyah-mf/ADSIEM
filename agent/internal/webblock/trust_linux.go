//go:build linux

package webblock

import (
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// Injectable for tests.
var (
	lookPath = exec.LookPath
	runTool  = func(name string, args ...string) error {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return errors.New(name + ": " + err.Error() + ": " + string(out))
		}
		return nil
	}
	debianAnchor = "/usr/local/share/ca-certificates/adsiem-webblock.crt"
	rhelAnchor   = "/etc/pki/ca-trust/source/anchors/adsiem-webblock.crt"
)

type trustTool struct {
	anchor string
	cmd    string
	args   []string
}

func trustTools() []trustTool {
	return []trustTool{
		{debianAnchor, "update-ca-certificates", nil},
		{rhelAnchor, "update-ca-trust", []string{"extract"}},
	}
}

func installTrust(der []byte, fingerprint string) error {
	for _, t := range trustTools() {
		if _, err := lookPath(t.cmd); err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(t.anchor), 0o755); err != nil {
			return err
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := writeFileAtomic(t.anchor, data, false); err != nil {
			return err
		}
		return runTool(t.cmd, t.args...)
	}
	return errors.New("no supported trust store tool")
}

func removeTrust(string) error {
	var firstErr error
	for _, t := range trustTools() {
		if _, err := os.Stat(t.anchor); err != nil {
			continue
		}
		if err := os.Remove(t.anchor); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := lookPath(t.cmd); err == nil {
			if err := runTool(t.cmd, t.args...); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// trustInstalled reports whether our anchor file holds the given CA.
func trustInstalled(fingerprint string) bool {
	for _, t := range trustTools() {
		b, err := os.ReadFile(t.anchor)
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(b); blk != nil && fingerprintOf(blk.Bytes) == fingerprint {
			return true
		}
	}
	return false
}

func protectKeyFile(path string) error { return os.Chmod(path, 0o600) }
