package malhash

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

// Path is the agent endpoint that returns changes above a seq.
const Path = "/api/ingest/malware-hashes"

// FileName is the saved set in the agent's state directory.
const FileName = "malware_hashes.bin"

const (
	retryEvery = time.Minute
	maxPages   = 500
)

// Poster is the part of client.Client the sync needs.
type Poster interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

type page struct {
	Action  string     `json:"action"`
	Version string     `json:"version"`
	Seq     int64      `json:"seq"`
	Reset   bool       `json:"reset"`
	More    bool       `json:"more"`
	Changes [][]string `json:"changes"`
}

// Store holds the current set and brings it to the version heartbeats name.
type Store struct {
	path string
	cur  atomic.Pointer[Set]

	mu      sync.Mutex
	want    string
	wantSet bool
	wake    chan struct{}

	// OnChange is called with each new set (also the one loaded from disk,
	// by Open's caller through Current).
	OnChange func(*Set)
}

// Open loads the saved set, if there is a readable one.
func Open(path string) *Store {
	s := &Store{path: path, wake: make(chan struct{}, 1)}
	set, err := Load(path)
	if err != nil {
		set = Empty()
	} else {
		slog.Info("malhash: known-malware hashes loaded", "hashes", set.Len(), "action", set.Action)
	}
	s.cur.Store(set)
	return s
}

// Current is the set in force.
func (s *Store) Current() *Set { return s.cur.Load() }

// File is where the set is saved (the fanotify helper loads it from there).
func (s *Store) File() string { return s.path }

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
				slog.Warn("malhash: could not sync known-malware hashes, will retry", "err", err)
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

// Sync fetches the changes since the current set (every page) and installs
// the result. want "" turns checking off and drops the set.
func (s *Store) Sync(ctx context.Context, c Poster, want string) error {
	cur := s.Current()
	if want == "" {
		if cur.Version == "" && cur.Len() == 0 {
			return nil
		}
		return s.install(Empty())
	}
	work, since, continuing := cur, cur.Seq, false
	for n := 0; ; n++ {
		if n == maxPages {
			return fmt.Errorf("%s: more than %d pages", Path, maxPages)
		}
		p, err := fetch(ctx, c, since, continuing)
		if err != nil {
			return err
		}
		if p.Action == ActionOff {
			return s.install(Empty())
		}
		work = work.apply(p.Reset && !continuing, p.Changes)
		since, continuing = p.Seq, true
		if !p.More {
			work.Seq, work.Action, work.Version = p.Seq, p.Action, p.Version
			break
		}
	}
	return s.install(work)
}

func (s *Store) install(set *Set) error {
	err := set.Save(s.path)
	if err != nil {
		// still enforce it; the next start downloads it again
		slog.Warn("malhash: could not save known-malware hashes", "path", s.path, "err", err)
	}
	s.cur.Store(set)
	slog.Info("malhash: known-malware hashes updated", "hashes", set.Len(), "action", set.Action, "seq", set.Seq)
	if s.OnChange != nil {
		s.OnChange(set)
	}
	return nil
}

func fetch(ctx context.Context, c Poster, since int64, continuing bool) (page, error) {
	var p page
	resp, err := c.PostContext(ctx, Path, map[string]any{"since": since, "continuing": continuing})
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
