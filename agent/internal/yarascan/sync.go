package yarascan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	return nil
}
