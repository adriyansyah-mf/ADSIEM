package ipblock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	retryEvery    = time.Minute
	maxPages      = 200
	maxSyncJitter = 60 * time.Second
)

// Poster is the part of client.Client the sync needs.
type Poster interface {
	PostContext(ctx context.Context, path string, payload any) (*http.Response, error)
}

type change struct {
	CIDR   string `json:"cidr"`
	Action string `json:"action"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type page struct {
	Group   string   `json:"group"`
	Mode    string   `json:"mode"`
	Seq     int64    `json:"seq"`
	Reset   bool     `json:"reset"`
	More    bool     `json:"more"`
	Version string   `json:"version"`
	Changes []change `json:"changes"`
}

// Store holds the current list and brings it to the version heartbeats name
// (heartbeat ip_blocklist_version, "<group>:<seq>:<mode>", "" = off).
type Store struct {
	path string
	cur  atomic.Pointer[List]

	mu      sync.Mutex
	want    string
	wantSet bool
	wake    chan struct{}

	// OnChange is called with each newly installed list.
	OnChange func(*List)

	// jitter is the delay before a routine update (same group and mode, list
	// already in force): a new entry reaches the fleet within a minute
	// instead of every agent asking at once. Replaced in tests.
	jitter func() time.Duration
}

// Open loads the saved list at path, if there is a readable one.
func Open(path string) *Store {
	s := &Store{path: path, wake: make(chan struct{}, 1),
		jitter: func() time.Duration { return rand.N(maxSyncJitter) }}
	l, err := Load(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("ipblock: saved list not loaded", "path", path, "err", err)
		}
		l = Empty()
	} else {
		slog.Info("ipblock: list loaded", "entries", len(l.Entries), "mode", l.Mode, "version", l.Version)
	}
	s.cur.Store(l)
	return s
}

// Current is the list in force.
func (s *Store) Current() *List { return s.cur.Load() }

// Want records the version the server's heartbeat names.
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

// routine: only the sequence moved (an entry was added or removed); the
// group, the mode and an active list are unchanged, so the sync may wait.
func routine(cur, want string) bool {
	if cur == "" || want == "" || cur == want {
		return false
	}
	c, w := strings.Split(strings.TrimSuffix(cur, "+"), ":"), strings.Split(strings.TrimSuffix(want, "+"), ":")
	return len(c) == 3 && len(w) == 3 && c[0] == w[0] && c[2] == w[2]
}

// SyncLoop syncs whenever the wanted version differs from the current one,
// retrying every minute until it works, until ctx ends.
func (s *Store) SyncLoop(ctx context.Context, c Poster) {
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	synced := false
	for {
		if want, need := s.wanted(); need {
			if synced && routine(s.Current().Version, want) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(s.jitter()):
				}
				want, need = s.wanted()
			}
			if need {
				sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				if err := s.Sync(sctx, c, want); err != nil {
					slog.Warn("ipblock: could not sync the IP blocklist, will retry", "err", err)
				}
				cancel()
				synced = true
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
	}
}

// Sync fetches every page of changes since the current list and installs
// the result. want "" turns the list off.
func (s *Store) Sync(ctx context.Context, c Poster, want string) error {
	cur := s.Current()
	if want == "" {
		if cur.Version == "" && len(cur.Entries) == 0 && cur.Mode == "off" {
			return nil
		}
		return s.install(Empty())
	}
	work, since, continuing := cur.clone(), cur.Seq, false
	if cur.Group != "" && !strings.HasPrefix(want, cur.Group+":") {
		work, since = Empty(), 0 // another group's sequence numbers mean nothing here
	}
	group := ""
	for n := 0; ; n++ {
		if n == maxPages {
			return fmt.Errorf("%s: more than %d pages", Path, maxPages)
		}
		p, err := fetch(ctx, c, since, continuing)
		if err != nil {
			return err
		}
		if p.Mode == "off" || p.Mode == "" {
			return s.install(Empty())
		}
		if continuing && p.Group != group {
			return fmt.Errorf("%s: group changed while paging (%q, then %q)", Path, group, p.Group)
		}
		group = p.Group
		if p.Reset {
			work.Entries = map[string]Entry{}
		}
		for _, ch := range p.Changes {
			switch ch.Action {
			case "block":
				work.Entries[ch.CIDR] = Entry{Source: ch.Source, Reason: ch.Reason}
			case "remove":
				delete(work.Entries, ch.CIDR)
			}
		}
		since, continuing = p.Seq, true
		if !p.More {
			work.Version, work.Seq, work.Group, work.Mode = p.Version, p.Seq, p.Group, p.Mode
			break
		}
	}
	return s.install(work)
}

func (s *Store) install(l *List) error {
	if l.Version == "" && len(l.Entries) == 0 {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			slog.Warn("ipblock: could not remove the saved list", "path", s.path, "err", err)
		}
	} else if err := l.Save(s.path); err != nil {
		// still enforce it; the next start downloads it again
		slog.Warn("ipblock: could not save the IP blocklist", "path", s.path, "err", err)
	}
	s.cur.Store(l)
	slog.Info("ipblock: IP blocklist updated", "entries", len(l.Entries), "mode", l.Mode, "version", l.Version)
	if s.OnChange != nil {
		s.OnChange(l)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&p); err != nil {
		return p, fmt.Errorf("%s: %w", Path, err)
	}
	return p, nil
}
