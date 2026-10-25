package yarascan

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const syncRetry = time.Minute

// Want records the rule-set hash the server advertised. SyncLoop loads
// it, retrying until it succeeds.
func (s *Scanner) Want(hash string) {
	s.wantMu.Lock()
	s.want, s.wantSet = hash, true
	s.wantMu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Scanner) wanted() (string, bool) {
	s.wantMu.Lock()
	defer s.wantMu.Unlock()
	return s.want, s.wantSet
}

// SyncLoop keeps the loaded rules at the wanted hash until ctx ends.
func (s *Scanner) SyncLoop(ctx context.Context, c Poster) {
	t := time.NewTicker(syncRetry)
	defer t.Stop()
	for {
		if want, ok := s.wanted(); ok && want != s.Hash() {
			sctx, cancel := context.WithTimeout(ctx, time.Minute)
			if err := s.Sync(sctx, c, want); err != nil {
				slog.Warn("yara: could not load rules from the server, will retry", "err", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
	}
}

type wantState struct {
	wantMu  sync.Mutex
	want    string
	wantSet bool
	wake    chan struct{}
}
