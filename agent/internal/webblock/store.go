package webblock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

	// jitter picks the delay before a fleet-wide update sync and pause waits
	// for it (false: ctx ended). Replaced in tests.
	jitter func() time.Duration
	pause  func(ctx context.Context, d time.Duration) bool
}

// maxSyncJitter spreads the fleet's syncs of a new list version over a minute
// so a feed refresh does not hit the server with every agent at once.
const maxSyncJitter = 60 * time.Second

func randomJitter() time.Duration { return rand.N(maxSyncJitter) }

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// groupOf is the part of a "<group>:<seq>" version before the last colon.
func groupOf(version string) string {
	if i := strings.LastIndex(version, ":"); i >= 0 {
		return version[:i]
	}
	return version
}

// Open loads the saved list at path (ListPath), if there is a readable one,
// and deletes the list an older agent left at <state>/webblock.json.
func Open(path string) *Store {
	s := &Store{path: path, wake: make(chan struct{}, 1), jitter: randomJitter, pause: sleepCtx}
	if dir := filepath.Dir(path); filepath.Base(dir) == CADirName {
		legacy := filepath.Join(filepath.Dir(dir), LegacyListFile)
		if err := os.Remove(legacy); err == nil {
			slog.Info("webblock: removed the old saved list", "path", legacy)
		} else if !os.IsNotExist(err) {
			slog.Warn("webblock: could not remove the old saved list", "path", legacy, "err", err)
		}
	}
	l, err := Load(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("webblock: saved blocklist not loaded", "path", path, "err", err)
		}
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
// retrying every minute until it works, until ctx ends. An update within the
// group of an active list waits a random 0-60s first; the first sync after
// start, turning on, and a group change do not (see jittered).
func (s *Store) SyncLoop(ctx context.Context, c Poster) {
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	synced := false  // a sync has run since start
	delayedFor := "" // the version the pause was already served for
	for {
		if want, need := s.wanted(); need {
			if synced && want != delayedFor && jittered(s.Current().Version, want) {
				delayedFor = want
				if !s.pause(ctx, s.jitter()) {
					return
				}
				// a newer heartbeat may have arrived meanwhile: sync what is wanted now
				want, need = s.wanted()
			}
			if need {
				sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				if err := s.Sync(sctx, c, want); err != nil {
					slog.Warn("webblock: could not sync web blocklist, will retry", "err", err)
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

// jittered reports whether moving from the installed version to want is a
// routine update (same group, list already active) that may wait.
func jittered(cur, want string) bool {
	return cur != "" && want != "" && want != cur && groupOf(cur) == groupOf(want)
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
	group := "" // the group of the first page of this pass
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
		if !continuing {
			group = p.Group
		} else if p.Group != group {
			// the group changed between pages: the pages so far are another
			// group's; start over once from zero
			if restarted {
				return fmt.Errorf("%s: group changed while paging (%q, then %q)", Path, group, p.Group)
			}
			work, since, rules, continuing, restarted = Empty(), 0, 0, false, true
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
	if l.Version == "" && len(l.Entries) == 0 {
		// off: nothing worth keeping (and no reason to create the directory)
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			slog.Warn("webblock: could not remove the saved blocklist", "path", s.path, "err", err)
		}
	} else if err := l.Save(s.path); err != nil {
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
