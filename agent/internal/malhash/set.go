// Package malhash keeps the server's known-malware SHA-256 set on the
// agent: synced as deltas (server-api/app/api/routes/malware_hashes.py),
// saved in the state directory so a restart does not download it again,
// and checked by the prevention engine on every exec and by the on-access
// scanner on every file written in a watched directory.
package malhash

import (
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/siem-platform/agent/internal/tlsh"
)

// Actions the server sends: off (nothing is checked), detect, block.
const (
	ActionOff    = "off"
	ActionDetect = "detect"
	ActionBlock  = "block"
)

// Set is an immutable snapshot of the known-malware hashes: sorted keys
// with a label index each (families repeat, so labels are stored once).
type Set struct {
	Seq     int64
	Action  string
	Version string
	keys    [][32]byte
	labels  []uint16
	table   []string
	// TLSH digests of the hashes that have one (sim[i] belongs to
	// keys[simKey[i]]), for Similar.
	sim    []tlsh.Hash
	simKey []int32
}

// entry is one hash's data while a set is built.
type entry struct{ label, tlsh string }

// Empty is the set before any sync (nothing is checked).
func Empty() *Set { return &Set{Action: ActionOff} }

// Similar returns the known-malware hash whose TLSH is closest to h, when
// at most maxDist away (its label, SHA-256 and the distance).
func (s *Set) Similar(h tlsh.Hash, maxDist int) (label, sha string, dist int, ok bool) {
	if s == nil {
		return "", "", 0, false
	}
	best, at := maxDist+1, -1
	for i := range s.sim {
		if d := tlsh.Distance(h, s.sim[i]); d < best {
			best, at = d, i
		}
	}
	if at < 0 {
		return "", "", 0, false
	}
	k := s.simKey[at]
	return s.table[s.labels[k]], hex.EncodeToString(s.keys[k][:]), best, true
}

// SimilarCount is the number of hashes with a TLSH digest.
func (s *Set) SimilarCount() int {
	if s == nil {
		return 0
	}
	return len(s.sim)
}

// New builds a set from sha256 -> label (malformed hashes are skipped).
func New(action string, hashes map[string]string) *Set {
	changes := make([][]string, 0, len(hashes))
	for h, l := range hashes {
		changes = append(changes, []string{h, l})
	}
	return newFrom(action, changes)
}

// NewWithTLSH builds a set from [sha256, label, tlsh] rows.
func NewWithTLSH(action string, rows [][]string) *Set { return newFrom(action, rows) }

func newFrom(action string, changes [][]string) *Set {
	s := Empty().apply(true, changes)
	s.Action = action
	return s
}

// Len is the number of hashes.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.keys)
}

// Active reports whether anything should be checked.
func (s *Set) Active() bool {
	return s != nil && len(s.keys) > 0 && (s.Action == ActionDetect || s.Action == ActionBlock)
}

// Block reports whether a match should be stopped, not only reported.
func (s *Set) Block() bool { return s != nil && s.Action == ActionBlock }

func parse(sha string) ([32]byte, bool) {
	var k [32]byte
	if len(sha) != 64 {
		return k, false
	}
	if _, err := hex.Decode(k[:], []byte(sha)); err != nil {
		return k, false
	}
	return k, true
}

// Lookup returns the label of a known-malware hash (lower- or upper-case hex).
func (s *Set) Lookup(sha string) (string, bool) {
	if s == nil || len(s.keys) == 0 {
		return "", false
	}
	k, ok := parse(sha)
	if !ok {
		return "", false
	}
	i := sort.Search(len(s.keys), func(i int) bool { return cmp(s.keys[i], k) >= 0 })
	if i == len(s.keys) || s.keys[i] != k {
		return "", false
	}
	return s.table[s.labels[i]], true
}

func cmp(a, b [32]byte) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// apply returns a new set with the server's changes: [sha256, label] or
// [sha256, label, tlsh] adds, [sha256] removes; reset starts from nothing.
// Malformed entries are skipped.
func (s *Set) apply(reset bool, changes [][]string) *Set {
	m := map[[32]byte]entry{}
	if !reset && s != nil {
		digests := map[int32]string{}
		for i, k := range s.simKey {
			digests[k] = s.sim[i].String()
		}
		for i, k := range s.keys {
			m[k] = entry{label: s.table[s.labels[i]], tlsh: digests[int32(i)]}
		}
	}
	for _, c := range changes {
		if len(c) == 0 {
			continue
		}
		k, ok := parse(c[0])
		if !ok {
			continue
		}
		if len(c) >= 2 {
			e := entry{label: c[1]}
			if len(c) >= 3 {
				e.tlsh = c[2]
			}
			m[k] = e
		} else {
			delete(m, k)
		}
	}
	return build(m)
}

func build(m map[[32]byte]entry) *Set {
	out := &Set{keys: make([][32]byte, 0, len(m))}
	for k := range m {
		out.keys = append(out.keys, k)
	}
	sort.Slice(out.keys, func(i, j int) bool { return cmp(out.keys[i], out.keys[j]) < 0 })
	idx := map[string]uint16{}
	out.labels = make([]uint16, len(out.keys))
	for i, k := range out.keys {
		l := m[k].label
		if d := m[k].tlsh; d != "" {
			if h, err := tlsh.Parse(d); err == nil {
				out.sim = append(out.sim, h)
				out.simKey = append(out.simKey, int32(i))
			}
		}
		n, ok := idx[l]
		if !ok {
			if len(out.table) == 0xFFFF {
				l = "" // more distinct labels than an index holds: the rest share ""
				n, ok = idx[l]
			}
			if !ok {
				n = uint16(len(out.table))
				idx[l] = n
				out.table = append(out.table, l)
			}
		}
		out.labels[i] = n
	}
	if len(out.table) == 0 {
		out.table = []string{""}
	}
	return out
}

// onDisk is the saved form (gob).
type onDisk struct {
	Format  int
	Seq     int64
	Action  string
	Version string
	Keys    []byte // 32 bytes each
	Labels  []uint16
	Table   []string
	// TLSH digests by key index ("" none). TLSHAware: saved by an agent that
	// keeps them; a set saved before is synced again in full once, so the
	// digests of hashes it already has arrive.
	TLSH      []string
	TLSHAware bool
}

const format = 1

// Save writes the set atomically (temp file, then rename).
func (s *Set) Save(path string) error {
	d := onDisk{Format: format, Seq: s.Seq, Action: s.Action, Version: s.Version, Labels: s.labels, Table: s.table,
		Keys: make([]byte, 0, 32*len(s.keys)), TLSHAware: true}
	for _, k := range s.keys {
		d.Keys = append(d.Keys, k[:]...)
	}
	if len(s.sim) > 0 {
		d.TLSH = make([]string, len(s.keys))
		for i, k := range s.simKey {
			d.TLSH[k] = s.sim[i].String()
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".malware_hashes-*")
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(tmp).Encode(d); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads a set saved by Save.
func Load(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var d onDisk
	if err := gob.NewDecoder(f).Decode(&d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if d.Format != format || len(d.Keys)%32 != 0 || len(d.Keys)/32 != len(d.Labels) {
		return nil, fmt.Errorf("%s: unknown or damaged format", path)
	}
	s := &Set{Seq: d.Seq, Action: d.Action, Version: d.Version, labels: d.Labels, table: d.Table,
		keys: make([][32]byte, len(d.Labels))}
	for i := range s.keys {
		copy(s.keys[i][:], d.Keys[32*i:32*i+32])
	}
	for i, l := range s.labels {
		if int(l) >= len(s.table) {
			return nil, fmt.Errorf("%s: label %d out of range", path, i)
		}
	}
	for i := 1; i < len(s.keys); i++ {
		if cmp(s.keys[i-1], s.keys[i]) >= 0 {
			return nil, fmt.Errorf("%s: keys not sorted", path)
		}
	}
	if len(d.TLSH) == len(s.keys) {
		for i, digest := range d.TLSH {
			if h, err := tlsh.Parse(digest); digest != "" && err == nil {
				s.sim = append(s.sim, h)
				s.simKey = append(s.simKey, int32(i))
			}
		}
	}
	if !d.TLSHAware {
		// from before TLSH: keep enforcing it, but sync everything again
		s.Seq, s.Version = 0, ""
	}
	return s, nil
}
