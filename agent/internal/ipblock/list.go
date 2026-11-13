// Package ipblock keeps the group's IP IoC blocklist (server-api
// app/services/ip_blocks.py) in sync, hands it to the firewall when the group
// policy's ip_ioc is "block", and reports connections to listed addresses as
// ioc_match lines whenever it is "detect" or "block".
package ipblock

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

// Path is the agent endpoint the list is synced from.
const Path = "/api/ingest/ip-blocklist"

// MaxEntries bounds the list an agent enforces: past it the newest entries
// are kept out (the firewall and the matcher stay fast) and health says so.
const MaxEntries = 50000

// Entry is why one CIDR is listed.
type Entry struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// List is one synced version of the blocklist.
type List struct {
	Group   string           `json:"group"`
	Seq     int64            `json:"seq"`
	Version string           `json:"version"`
	Mode    string           `json:"mode"` // off, detect, block
	Entries map[string]Entry `json:"entries"`
}

// Empty is the list of an agent with ip_ioc off.
func Empty() *List { return &List{Mode: "off", Entries: map[string]Entry{}} }

func (l *List) clone() *List {
	c := *l
	c.Entries = make(map[string]Entry, len(l.Entries))
	for k, v := range l.Entries {
		c.Entries[k] = v
	}
	return &c
}

// CIDRs is the sorted list, capped at MaxEntries.
func (l *List) CIDRs() []string {
	out := make([]string, 0, len(l.Entries))
	for c := range l.Entries {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) > MaxEntries {
		out = out[:MaxEntries]
	}
	return out
}

// Save writes the list atomically, readable by root/SYSTEM only.
func (l *List) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a saved list; entries that do not parse are dropped.
func Load(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l := Empty()
	if err := json.Unmarshal(data, l); err != nil {
		return nil, err
	}
	if l.Entries == nil {
		l.Entries = map[string]Entry{}
	}
	for c := range l.Entries {
		if _, err := netip.ParsePrefix(c); err != nil {
			delete(l.Entries, c)
		}
	}
	return l, nil
}
