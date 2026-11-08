package webblock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	retryEvery = time.Minute
	maxPages   = 500
)

// Poster is the part of client.Client the sync needs.
type Poster interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

type change struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type page struct {
	Group   string   `json:"group"`
	Seq     int64    `json:"seq"`
	Reset   bool     `json:"reset"`
	More    bool     `json:"more"`
	Rules   int64    `json:"rules"`
	Version string   `json:"version"`
	Policy  Policy   `json:"policy"`
	Changes []change `json:"changes"`
}

// Store holds the current list and brings it to the version heartbeats name.
type Store struct {
	path string
	cur  atomic.Pointer[List]

	mu      sync.Mutex
	want    string
	wantSet bool
	wake    chan struct{}

	// OnChange is called with each newly installed list (the one loaded from
	// disk is read through Current by Open's caller).
	OnChange func(*List)
}

// Open loads the saved list, if there is a readable one.
func Open(path string) *Store {
	s := &Store{path: path, wake: make(chan struct{}, 1)}
	l, err := Load(path)
	if err != nil {
		l = Empty()
	} else {
		slog.Info("webblock: blocklist loaded", "domains", len(l.Entries), "version", l.Version)
	}
	s.cur.Store(l)
	return s
}

// Current is the list in force.
func (s *Store) Current() *List { return s.cur.Load() }

// Want records the version the server's heartbeat names ("" = off).
func (s *Store) Want(version string) {
	s.mu.Lock()
	s.want, s.wantSet = version, true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Store) wanted() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.wantSet {
		return "", false
	}
	return s.want, s.want != s.Current().Version
}

// SyncLoop syncs whenever the wanted version differs from the current one,
// retrying every minute until it works, until ctx ends.
func (s *Store) SyncLoop(ctx context.Context, c Poster) {
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	for {
		if want, need := s.wanted(); need {
			sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			if err := s.Sync(sctx, c, want); err != nil {
				slog.Warn("webblock: could not sync web blocklist, will retry", "err", err)
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

// Sync fetches the changes since the current list (every page) and installs
// the result. want "" turns web protection off and drops the list.
func (s *Store) Sync(ctx context.Context, c Poster, want string) error {
	cur := s.Current()
	if want == "" {
		if cur.Version == "" && len(cur.Entries) == 0 {
			return nil
		}
		return s.install(Empty())
	}
	work, since, rules, continuing, restarted := cur.clone(), cur.Seq, cur.Rules, false, false
	for n := 0; ; n++ {
		if n == maxPages {
			return fmt.Errorf("%s: more than %d pages", Path, maxPages)
		}
		p, err := fetch(ctx, c, since, continuing, rules)
		if err != nil {
			return err
		}
		if !p.Policy.Enabled {
			return s.install(Empty())
		}
		if !continuing && !restarted && cur.Group != "" && p.Group != cur.Group {
			// another group's sequence numbers mean nothing here: start over
			work, since, rules, restarted = Empty(), 0, 0, true
			n = -1
			continue
		}
		if p.Reset {
			work.Entries = map[string]Entry{}
		}
		if p.Reset || !continuing {
			rules = p.Rules
		}
		for _, ch := range p.Changes {
			switch ch.Action {
			case "block":
				work.Entries[ch.Domain] = Entry{Source: ch.Source, Reason: ch.Reason}
			case "remove":
				delete(work.Entries, ch.Domain)
			}
		}
		since, continuing = p.Seq, true
		if !p.More {
			work.Version, work.Seq, work.Rules, work.Group, work.Policy = p.Version, p.Seq, rules, p.Group, p.Policy
			break
		}
	}
	return s.install(work)
}

func (s *Store) install(l *List) error {
	if err := l.Save(s.path); err != nil {
		// still enforce it; the next start downloads it again
		slog.Warn("webblock: could not save web blocklist", "path", s.path, "err", err)
	}
	s.cur.Store(l)
	slog.Info("webblock: web blocklist updated", "domains", len(l.Entries), "version", l.Version, "seq", l.Seq)
	if s.OnChange != nil {
		s.OnChange(l)
	}
	return nil
}

func fetch(ctx context.Context, c Poster, since int64, continuing bool, rules int64) (page, error) {
	var p page
	resp, err := c.PostContext(ctx, Path, map[string]any{"since": since, "continuing": continuing, "rules": rules})
	if err != nil {
		return p, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return p, fmt.Errorf("%s: status %d", Path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&p); err != nil {
		return p, fmt.Errorf("%s: %w", Path, err)
	}
	return p, nil
}
