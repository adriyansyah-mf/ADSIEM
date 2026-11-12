package yarascan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/siem-platform/agent/internal/rulecache"
)

// RulesPath is the agent endpoint that returns the enabled rule set.
const RulesPath = "/api/ingest/yara-rules"

type rulesResponse struct {
	Hash  string `json:"hash"`
	Rules []Rule `json:"rules"`
}

// Poster is the part of client.Client that Sync needs.
type Poster interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

// Sync fetches the server's rules when hash (from the heartbeat) differs
// from the loaded set. An empty hash means the server has no rules.
func (s *Scanner) Sync(ctx context.Context, c Poster, hash string) error {
	if hash == s.Hash() {
		return nil
	}
	if hash == "" {
		s.SetRules("", nil)
		s.dropCache()
		return nil
	}
	resp, err := c.PostContext(ctx, RulesPath, map[string]any{"loaded_hash": s.Hash()})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", RulesPath, resp.StatusCode)
	}
	var body rulesResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&body); err != nil {
		return fmt.Errorf("%s: %w", RulesPath, err)
	}
	s.SetRules(body.Hash, body.Rules)
	if s.opts.CacheFile != "" {
		if err := rulecache.Save(s.opts.CacheFile, body.Hash, body.Rules); err != nil {
			slog.Warn("yara: could not cache rules", "err", err)
		}
	}
	return nil
}

// LoadCache loads the rules cached by the last sync (New calls it).
func (s *Scanner) LoadCache() {
	if s.opts.CacheFile == "" {
		return
	}
	var rules []Rule
	hash, err := rulecache.Load(s.opts.CacheFile, &rules)
	if err != nil {
		if !errors.Is(err, rulecache.ErrNone) {
			slog.Warn("yara: cached rules not used", "err", err)
		}
		return
	}
	slog.Info("yara: using cached rules until the server answers", "sources", len(rules))
	s.SetRules(hash, rules)
}

func (s *Scanner) dropCache() {
	if s.opts.CacheFile == "" {
		return
	}
	if err := os.Remove(s.opts.CacheFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("yara: could not remove cached rules", "err", err)
	}
}
