// Package webblock enforces the server's web blocklist on the endpoint: it
// keeps the list in sync, redirects blocked domains to a local block page and
// removes everything again when the feature is turned off.
package webblock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Path is the agent endpoint that returns blocklist changes above a seq.
const Path = "/api/ingest/web-blocklist"

// ListFile is the saved list, kept in the protected <state>/webblock
// directory next to the CA files.
const ListFile = "list.json"

// LegacyListFile is where agents before this version saved the list
// (<state>/webblock.json, outside the protected directory). It is deleted,
// never loaded.
const LegacyListFile = "webblock.json"

// ListPath is the saved list's path for a state directory.
func ListPath(stateDir string) string { return filepath.Join(caDir(stateDir), ListFile) }

// defaultMaxEntries applies when the policy does not set a limit.
const defaultMaxEntries = 50000

// Policy is the server's web protection policy for the agent's group.
type Policy struct {
	Enabled    bool   `json:"enabled"`
	PageHTML   string `json:"page_html"`
	Contact    string `json:"contact"`
	MaxEntries int    `json:"max_entries"`
}

// Entry says where a blocked domain came from.
type Entry struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// List is the blocklist in force. A list is never modified after it is
// installed; a sync builds a new one.
type List struct {
	Version string           `json:"version"`
	Group   string           `json:"group"`
	Seq     int64            `json:"seq"`
	Rules   int64            `json:"rules"`
	Policy  Policy           `json:"policy"`
	Entries map[string]Entry `json:"entries"`
}

// Empty is the list that blocks nothing.
func Empty() *List { return &List{Entries: map[string]Entry{}} }

// Active reports whether the list should be enforced.
func (l *List) Active() bool { return l.Version != "" && l.Policy.Enabled }

// clone copies the list so a sync can change it without touching the
// installed one.
func (l *List) clone() *List {
	c := *l
	c.Entries = make(map[string]Entry, len(l.Entries))
	for k, v := range l.Entries {
		c.Entries[k] = v
	}
	return &c
}

func sourceRank(s string) int {
	switch s {
	case "manual":
		return 0
	case "alert":
		return 1
	}
	return 2
}

// Selected is the domains to enforce: at most Policy.MaxEntries (50000 when
// unset), manual entries first, then alert-driven ones, then the rest; domain
// name breaks ties so the choice is deterministic.
func (l *List) Selected() []string {
	names := make([]string, 0, len(l.Entries))
	for d := range l.Entries {
		names = append(names, d)
	}
	sort.Slice(names, func(i, j int) bool {
		ri, rj := sourceRank(l.Entries[names[i]].Source), sourceRank(l.Entries[names[j]].Source)
		if ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	max := l.Policy.MaxEntries
	if max <= 0 {
		max = defaultMaxEntries
	}
	if len(names) > max {
		names = names[:max]
	}
	return names
}

// wwwSource reports whether a domain from this source also blocks its www.
// name: only operator-chosen entries do, feed entries are exact hosts.
func wwwSource(s string) bool { return s == "manual" || s == "alert" }

// bareDomains is the subset of domains whose source gets no www. line.
func (l *List) bareDomains(domains []string) map[string]bool {
	var bare map[string]bool
	for _, d := range domains {
		if !wwwSource(l.Entries[d].Source) {
			if bare == nil {
				bare = map[string]bool{}
			}
			bare[d] = true
		}
	}
	return bare
}

// Save writes the list to path with the CA files' helpers: the directory is
// created or verified as private (Linux: owned by euid, 0700; Windows:
// SYSTEM and Administrators only), the file goes through a private temp file
// that is fsynced before the rename.
func (l *List) Save(path string) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return writeSecretFile(filepath.Dir(path), filepath.Base(path), b)
}

// Load reads a saved list. Like the CA files it must be a regular file owned
// by the agent user (Linux) or SYSTEM/Administrators (Windows) in a private
// directory.
func Load(path string) (*List, error) {
	if _, err := os.Lstat(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := secureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := checkSecretFile(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l := Empty()
	if err := json.Unmarshal(b, l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.Entries == nil {
		l.Entries = map[string]Entry{}
	}
	return l, nil
}
