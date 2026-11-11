package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/siem-platform/agent/internal/client"
	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/update"
)

// UpdateKeys are the release signing keys trusted for self-update, set at
// build time: -ldflags "-X main.UpdateKeys=<base64 ed25519 public key>[,...]".
var UpdateKeys = ""

// newUpdater builds the self-updater: built-in keys plus update.trusted_keys;
// a bad configured key is skipped, never trusted.
func newUpdater(cfg *config.Config, c *client.Client) *update.Updater {
	var keys []ed25519.PublicKey
	for _, src := range append([]string{UpdateKeys}, cfg.Update.TrustedKeys...) {
		k, err := update.ParseKeys(src)
		if err != nil {
			slog.Warn("update key ignored", "err", err)
			continue
		}
		keys = append(keys, k...)
	}
	kind, kindErr := update.DetectKind()
	if cfg.Update.Disabled {
		kindErr = errors.New("disabled in config (update.disabled)")
	}
	fetch := func(ctx context.Context, path string, w io.Writer) error {
		if !strings.HasPrefix(path, "/api/agent/update/package/") {
			return fmt.Errorf("offer names %q, not an update package path", path)
		}
		// resumes after a dropped connection (Range): a lossy link cut a
		// 7.5 MB MSI at 48% and the whole attempt failed (2026-11-11)
		return c.Download(ctx, path, client.WriterErrors(w))
	}
	u := update.New(cfg.Agent.StateDir, Version, keys, kind, kindErr, fetch, update.InstallPackage)
	if !cfg.Update.Disabled {
		u.Redetect(update.DetectKind) // the MSI registers itself after it starts the service
	}
	s := u.Status()
	slog.Info("self-update", "state", s.State, "kind", s.Kind, "trusted_keys", len(keys), "reason", s.Error)
	return u
}
