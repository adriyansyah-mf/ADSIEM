// Package rollback keeps point-in-time copies of the folders where user data
// lives and puts files back after ransomware was stopped.
//
// Snapshot copies every regular file under the protected roots into
// <Dir>/snapshots/<unix time>/, mirroring its path. A file unchanged since
// the previous snapshot (same size and modification time) is a hard link to
// the previous copy, so a snapshot costs only what changed. Old snapshots go
// when there are more than Keep or the store is over Quota.
//
// Restore is called when RansomGuard stopped a process: for the folders it
// wrote in, every file of the newest snapshot taken before the attack began
// that is missing now or was modified since is copied back. What the
// ransomware left in its place (the encrypted file, or a renamed copy such
// as report.docx.locked) is moved to <Dir>/displaced/<time>/, never deleted,
// so a wrong restore can be undone by hand.
//
// The same code runs on Windows and Linux (no Volume Shadow Copy: ransomware
// deletes those first, and Linux has no equivalent). The store is only as
// safe as the agent's state directory: root/SYSTEM only.
package rollback

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LogType of the lines (decoders/ransomware_rollback.yaml).
const LogType = "ransomware_rollback"

// Defaults.
const (
	DefaultKeep    = 24
	DefaultQuota   = 5 << 30   // bytes for all snapshots
	DefaultMaxFile = 100 << 20 // larger files are not kept
	indexName      = "index.jsonl"
	clockSlack     = 2 * time.Second
)

// Store is the snapshot store of one host.
type Store struct {
	Dir     string   // <state dir>/rollback
	Roots   []string // protected folders (absolute)
	Keep    int
	Quota   int64
	MaxFile int64
	// Skip, when set, leaves a path out (caches, the store itself).
	Skip func(path string) bool

	mu sync.Mutex // one snapshot or restore at a time
}

// entry is one file in a snapshot index.
type entry struct {
	Path  string `json:"p"`
	Size  int64  `json:"s"`
	MTime int64  `json:"m"` // unix nanoseconds
}

func (s *Store) keep() int {
	if s.Keep > 0 {
		return s.Keep
	}
	return DefaultKeep
}

func (s *Store) quota() int64 {
	if s.Quota > 0 {
		return s.Quota
	}
	return DefaultQuota
}

func (s *Store) maxFile() int64 {
	if s.MaxFile > 0 {
		return s.MaxFile
	}
	return DefaultMaxFile
}

func (s *Store) snapDir() string { return filepath.Join(s.Dir, "snapshots") }

// mirror is where path is kept inside snapshot dir snap: the volume becomes
// a folder (C:\Users\a\x.docx -> <snap>/C/Users/a/x.docx).
func mirror(snap, path string) string {
	p := filepath.Clean(path)
	if v := filepath.VolumeName(p); v != "" {
		p = strings.TrimSuffix(strings.TrimPrefix(v, `\\?\`), ":") + p[len(v):]
	}
	return filepath.Join(snap, p)
}

// Snapshots lists the snapshot times, oldest first.
func (s *Store) Snapshots() []time.Time {
	ents, _ := os.ReadDir(s.snapDir())
	var out []time.Time
	for _, e := range ents {
		if n, err := strconv.ParseInt(e.Name(), 10, 64); err == nil && e.IsDir() {
			if _, err := os.Stat(filepath.Join(s.snapDir(), e.Name(), indexName)); err == nil {
				out = append(out, time.Unix(0, n))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

func (s *Store) snapPath(t time.Time) string {
	return filepath.Join(s.snapDir(), strconv.FormatInt(t.UnixNano(), 10))
}

func readIndex(snap string) (map[string]entry, error) {
	f, err := os.Open(filepath.Join(snap, indexName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]entry{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Path != "" {
			out[e.Path] = e
		}
	}
	return out, sc.Err()
}

// SnapshotStats says what one snapshot did.
type SnapshotStats struct {
	When    time.Time
	Files   int
	Copied  int   // new or changed files copied
	Linked  int   // unchanged files linked to the previous snapshot
	Bytes   int64 // bytes copied
	Skipped int   // too large, unreadable or changed while copied
	Removed int   // old snapshots removed
}

// Snapshot takes a snapshot of the roots now.
func (s *Store) Snapshot() (SnapshotStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	st := SnapshotStats{When: now}
	if err := os.MkdirAll(s.snapDir(), 0o700); err != nil {
		return st, err
	}
	var prevSnap string
	prev := map[string]entry{}
	if snaps := s.Snapshots(); len(snaps) > 0 {
		prevSnap = s.snapPath(snaps[len(snaps)-1])
		prev, _ = readIndex(prevSnap)
	}
	tmp := filepath.Join(s.snapDir(), ".tmp-"+strconv.FormatInt(now.UnixNano(), 10))
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return st, err
	}
	idx, err := os.Create(filepath.Join(tmp, indexName))
	if err != nil {
		os.RemoveAll(tmp)
		return st, err
	}
	w := bufio.NewWriter(idx)
	enc := json.NewEncoder(w)
	abs, _ := filepath.Abs(s.Dir)
	for _, root := range s.Roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable: skip, keep walking
			}
			if d.IsDir() {
				if p == abs || strings.HasPrefix(p, abs+string(filepath.Separator)) || (s.Skip != nil && s.Skip(p)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || (s.Skip != nil && s.Skip(p)) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			st.Files++
			if info.Size() > s.maxFile() {
				st.Skipped++
				return nil
			}
			e := entry{Path: p, Size: info.Size(), MTime: info.ModTime().UnixNano()}
			dst := mirror(tmp, p)
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				st.Skipped++
				return nil
			}
			if old, ok := prev[p]; ok && old.Size == e.Size && old.MTime == e.MTime {
				if os.Link(mirror(prevSnap, p), dst) == nil {
					st.Linked++
					_ = enc.Encode(e)
					return nil
				}
			}
			n, err := copyStable(p, dst, info)
			if err != nil {
				st.Skipped++
				return nil
			}
			st.Copied++
			st.Bytes += n
			_ = enc.Encode(e)
			return nil
		})
	}
	if err := w.Flush(); err != nil {
		idx.Close()
		os.RemoveAll(tmp)
		return st, err
	}
	idx.Close()
	final := s.snapPath(now)
	if err := os.Rename(tmp, final); err != nil {
		os.RemoveAll(tmp)
		return st, err
	}
	st.Removed = s.prune()
	return st, nil
}

// copyStable copies src to dst; the file must not change while it is read
// (size and mtime equal before and after), else it is skipped this time.
func copyStable(src, dst string, before fs.FileInfo) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		after, serr := os.Stat(src)
		if serr != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			err = errors.New("changed while copied")
		}
	}
	if err != nil {
		os.Remove(dst)
		return 0, err
	}
	_ = os.Chtimes(dst, before.ModTime(), before.ModTime())
	return n, nil
}

// prune removes the oldest snapshots beyond Keep or over Quota (the newest
// one always stays). A file's blocks are freed only when no snapshot links
// it any more, so the size of a snapshot is what it alone holds.
func (s *Store) prune() int {
	snaps := s.Snapshots()
	removed := 0
	for len(snaps) > 1 && (len(snaps) > s.keep() || s.used() > s.quota()) {
		if os.RemoveAll(s.snapPath(snaps[0])) == nil {
			removed++
		}
		snaps = snaps[1:]
	}
	return removed
}

// used is the bytes the snapshots take, each inode counted once.
func (s *Store) used() int64 {
	var total int64
	seen := map[fileID]bool{}
	_ = filepath.WalkDir(s.snapDir(), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if id, ok := idOf(p, info); ok {
			if seen[id] {
				return nil
			}
			seen[id] = true
		}
		total += info.Size()
		return nil
	})
	return total
}

// Result says what a restore did.
type Result struct {
	Snapshot  time.Time // the snapshot restored from (zero: none before the attack)
	Restored  []string
	Displaced int // files moved aside (encrypted versions, renamed copies)
	Failed    []string
	Errors    []string
}

// Restore puts back the files of folders dirs (only files directly in them)
// from the newest snapshot taken before since: those missing now, or
// modified at or after since. Files created in those folders since then
// whose name is a restored file's name plus an extension (report.docx ->
// report.docx.locked) are moved aside too.
func (s *Store) Restore(dirs []string, since time.Time) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res Result
	var snap time.Time
	for _, t := range s.Snapshots() {
		if t.Before(since) {
			snap = t
		}
	}
	if snap.IsZero() {
		res.Errors = append(res.Errors, "no snapshot from before "+since.UTC().Format(time.RFC3339))
		return res
	}
	res.Snapshot = snap
	sp := s.snapPath(snap)
	// file times and the sensor's clock can be a little apart: a file
	// written up to clockSlack before the first event counts as the attack's
	cutoff := since.Add(-clockSlack)
	idx, err := readIndex(sp)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	want := map[string]bool{}
	for _, d := range dirs {
		want[normDir(d)] = true
	}
	displaced := filepath.Join(s.Dir, "displaced", strconv.FormatInt(time.Now().UnixNano(), 10))
	moveAside := func(p string) {
		dst := mirror(displaced, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err == nil {
			if err := os.Rename(p, dst); err == nil {
				res.Displaced++
				return
			}
			if _, err := copyFile(p, dst); err == nil && os.Remove(p) == nil {
				res.Displaced++
				return
			}
		}
		res.Errors = append(res.Errors, "could not move aside "+p)
	}
	restoredByDir := map[string][]string{}
	paths := make([]string, 0, len(idx))
	for p := range idx {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		e := idx[p]
		if !want[normDir(filepath.Dir(p))] {
			continue
		}
		cur, err := os.Lstat(p)
		switch {
		case err == nil && cur.Mode().IsRegular() && cur.ModTime().Before(cutoff) &&
			cur.Size() == e.Size && cur.ModTime().UnixNano() == e.MTime:
			continue // untouched
		case err == nil && cur.Mode().IsRegular() && cur.ModTime().Before(cutoff) &&
			!(encrypted(p) && !encrypted(mirror(sp, p))):
			// changed before the attack: a user's edit, not ours to undo
			// (unless it now reads as random data and did not before: some
			// ransomware puts the old modification time back)
			continue
		case err == nil:
			moveAside(p)
		case !errors.Is(err, fs.ErrNotExist):
			res.Failed = append(res.Failed, p)
			continue
		}
		if _, err := copyFile(mirror(sp, p), p); err != nil {
			res.Failed = append(res.Failed, p)
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		mt := time.Unix(0, e.MTime)
		_ = os.Chtimes(p, mt, mt)
		res.Restored = append(res.Restored, p)
		restoredByDir[filepath.Dir(p)] = append(restoredByDir[filepath.Dir(p)], filepath.Base(p))
	}
	// renamed copies: <restored name>.<ext>, created since the attack began
	for dir, names := range restoredByDir {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			for _, n := range names {
				if strings.HasPrefix(e.Name(), n+".") {
					if info, err := e.Info(); err == nil && !info.ModTime().Before(cutoff) {
						moveAside(filepath.Join(dir, e.Name()))
					}
					break
				}
			}
		}
	}
	return res
}

// encrypted: the first 64 KB read as random data (at least 7.5 bits of
// entropy per byte over at least 4 KB). Compressed formats (zip-based
// Office files, JPEG) score high too, which is why a restore also needs
// the snapshot copy to score low.
func encrypted(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, buf)
	if n < 4096 {
		return false
	}
	var hist [256]float64
	for _, c := range buf[:n] {
		hist[c]++
	}
	e := 0.0
	for _, h := range hist {
		if h > 0 {
			p := h / float64(n)
			e -= p * math.Log2(p)
		}
	}
	return e >= 7.5
}

func normDir(d string) string {
	d = filepath.Clean(d)
	if runtime.GOOS == "windows" {
		d = strings.ToLower(d)
	}
	return d
}

func copyFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, err
	}
	tmp := dst + ".adsiem-restore"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// Line is the log line of a restore.
func (r Result) Line(pid uint32, image string, since time.Time) string {
	q := func(s string) string { return strconv.Quote(s) }
	snap := ""
	if !r.Snapshot.IsZero() {
		snap = r.Snapshot.UTC().Format(time.RFC3339)
	}
	sample := ""
	if len(r.Restored) > 0 {
		sample = r.Restored[0]
	}
	return fmt.Sprintf("event=ransomware_rollback pid=%d image=%s since=%s snapshot=%s restored=%d displaced=%d failed=%d sample=%s error=%s",
		pid, q(image), since.UTC().Format(time.RFC3339), q(snap), len(r.Restored), r.Displaced, len(r.Failed),
		q(sample), q(strings.Join(r.Errors, "; ")))
}

// SnapshotLine is the log line of a snapshot (one a day at most is sent;
// see Controller).
func (st SnapshotStats) Line(err error) string {
	e := ""
	if err != nil {
		e = err.Error()
	}
	return fmt.Sprintf("event=rollback_snapshot files=%d copied=%d linked=%d bytes=%d skipped=%d removed=%d error=%s",
		st.Files, st.Copied, st.Linked, st.Bytes, st.Skipped, st.Removed, strconv.Quote(e))
}
