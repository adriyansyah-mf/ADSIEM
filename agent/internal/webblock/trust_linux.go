//go:build linux

package webblock

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const toolTimeout = 2 * time.Minute

// Injectable for tests.
var (
	lookPath = exec.LookPath
	// runTool runs the absolute tool path with a timeout.
	runTool = func(path string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if err != nil {
			return errors.New(filepath.Base(path) + ": " + err.Error() + ": " + string(out))
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

// writePublicFile writes a world-readable file through a random temp file in
// the same directory and a rename.
func writePublicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

func installTrust(der []byte, fingerprint string) error {
	for _, t := range trustTools() {
		tool, err := lookPath(t.cmd)
		if err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(t.anchor), 0o755); err != nil {
			return err
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := writePublicFile(t.anchor, data); err != nil {
			return err
		}
		if err := runTool(tool, t.args...); err != nil {
			// Do not leave an anchor that looks installed: the next Ensure retries.
			os.Remove(t.anchor)
			return err
		}
		return nil
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
		if tool, err := lookPath(t.cmd); err == nil {
			if err := runTool(tool, t.args...); err != nil && firstErr == nil {
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
