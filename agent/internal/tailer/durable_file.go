package tailer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/siem-platform/agent/internal/evidence"
)

const (
	fileSourcePrefix = "file:"   // cursor source of one file: file:<path>
	markerPrefix     = "source:" // configured path or glob has been enabled before
	durablePoll      = 200 * time.Millisecond
	discoverEvery    = 2 * time.Second
	readChunk        = 64 << 10
	passBudget       = 1 << 20 // bytes read from one file before giving others a turn
	maxPressureWait  = 5 * time.Second
)

// DurableSink admits one draft durably; *evidence.Publisher implements it.
type DurableSink interface {
	Submit(context.Context, evidence.Draft) (evidence.Envelope, error)
}

// trackedFile is one open file. offset is the committed cursor: the byte just
// after the last complete line that was admitted (or skipped as oversized).
// Bytes read past it wait in pending until their line completes.
type trackedFile struct {
	key, path            string
	f                    *os.File
	identity, generation string
	offset               int64
	pending              []byte
	pendingStart         int64 // file offset of pending[0]
	readPos              int64 // file offset of the next read
	discarding           bool  // inside a line longer than the event limit
	fingerprint          string
	fingerprintLen       int64 // bytes the fingerprint covers
}

type durableTail struct {
	ctx           context.Context
	path, logType string
	glob          bool
	j             *evidence.Journal
	sink          DurableSink
	health        string // source name in evidence health: one per configured path
	state         string // last health state written
	maxLine       int
	files         map[string]*trackedFile
	lastDiscover  time.Time
	scratch       []byte
}

// TailDurable follows path (a file or a glob) into the journal through sink,
// resuming from durable cursors: a restart neither skips nor repeats complete
// lines. The first enablement of a path starts at EOF (no history backfill);
// files that appear later are read from their start. It returns nil when ctx
// is canceled.
func TailDurable(ctx context.Context, path, logType string, j *evidence.Journal, sink DurableSink) error {
	t := &durableTail{
		ctx: ctx, path: path, logType: logType, glob: isGlob(path), j: j, sink: sink,
		health: fileSourcePrefix + path, maxLine: j.MaxEventBytes(),
		files: map[string]*trackedFile{}, scratch: make([]byte, readChunk),
	}
	defer t.closeAll()
	marker := markerPrefix + path
	_, enabledBefore := j.Cursor(marker)
	if err := t.discover(!enabledBefore); err != nil {
		return t.done(err)
	}
	if !enabledBefore {
		if err := t.control(func() error {
			return j.SaveBaseline(ctx, evidence.Cursor{Source: marker, Generation: newGeneration(), Identity: "configured", Empty: true})
		}); err != nil {
			return t.done(err)
		}
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(t.lastDiscover) >= discoverEvery {
			if err := t.discover(false); err != nil {
				return t.done(err)
			}
		}
		progressed := false
		for _, key := range t.sortedKeys() {
			moved, err := t.step(t.files[key])
			if err != nil {
				return t.done(err)
			}
			progressed = progressed || moved
		}
		if !progressed && !sleepCtx(ctx, durablePoll) {
			return nil
		}
	}
}

// done turns cancellation into a clean stop.
func (t *durableTail) done(err error) error {
	if t.ctx.Err() != nil {
		return nil
	}
	return err
}

func (t *durableTail) sortedKeys() []string {
	keys := make([]string, 0, len(t.files))
	for key := range t.files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (t *durableTail) closeAll() {
	for _, tf := range t.files {
		tf.f.Close()
	}
}

// matches lists the configured files that exist now, in a stable order.
func (t *durableTail) matches() []string {
	if !t.glob {
		if _, err := os.Stat(t.path); err != nil {
			return nil
		}
		return []string{t.path}
	}
	found, _ := filepath.Glob(t.path)
	sort.Strings(found)
	return found
}

func (t *durableTail) inScope(path string) bool {
	if !t.glob {
		return path == t.path
	}
	ok, _ := filepath.Match(t.path, path)
	return ok
}

// discover starts every matching file not tracked yet. firstEnable puts files
// that exist at the first enablement at EOF.
func (t *durableTail) discover(firstEnable bool) error {
	t.lastDiscover = time.Now()
	found := t.matches()
	if len(found) == 0 && !t.glob {
		t.setState("unavailable", "missing")
	}
	open := map[string]bool{}
	for _, tf := range t.files {
		open[tf.identity] = true
	}
	for _, path := range found {
		key := fileSourcePrefix + path
		if _, tracked := t.files[key]; tracked {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			t.setState("unavailable", "open_error")
			continue
		}
		id, err := fileIdentity(f)
		if err != nil {
			f.Close()
			if errors.Is(err, evidence.ErrUnsupported) {
				return err
			}
			t.setState("unavailable", "identity_error")
			continue
		}
		if open[id] { // the same file under another name, still being drained
			f.Close()
			continue
		}
		tf, err := t.startFile(key, path, f, id, firstEnable)
		if err != nil {
			f.Close()
			return err
		}
		t.files[key] = tf
		open[id] = true
	}
	return nil
}

// startFile decides where reading starts from the committed cursors.
func (t *durableTail) startFile(key, path string, f *os.File, id string, firstEnable bool) (*trackedFile, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	tf := &trackedFile{key: key, path: path, f: f, identity: id}
	saved, ok := t.j.Cursor(key)
	resume := func(c evidence.Cursor) error {
		// truncated below the committed offset, or another file that reuses the
		// inode / file index (deleted and recreated while stopped): unread
		// bytes of the old file are gone and this one is read from the start
		if size < c.Offset || !sameContent(f, c.Bookmark) {
			if err := t.gap(); err != nil {
				return err
			}
			return t.fresh(tf, 0)
		}
		tf.generation, tf.offset = c.Generation, c.Offset
		tf.fingerprint, tf.fingerprintLen = c.Bookmark, fingerprintLen(c.Bookmark)
		return nil
	}
	switch {
	case ok && saved.Identity == id:
		err = resume(saved)
	case ok && saved.Identity == "": // the previous file at this path was fully drained
		err = t.fresh(tf, 0)
	default:
		if c, moved := t.movedCursor(f, id, key); moved { // renamed inside the scope while stopped
			if err = resume(c); err == nil && tf.offset == c.Offset {
				err = t.baseline(tf)
			}
			break
		}
		switch {
		case ok: // another file replaced the one we were reading
			if !t.identityInScope(saved.Identity, key) {
				if err = t.gap(); err != nil {
					break
				}
			}
			err = t.fresh(tf, 0)
		case firstEnable:
			err = t.fresh(tf, size)
		default: // a file that appeared after enablement
			err = t.fresh(tf, 0)
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(tf.offset, io.SeekStart); err != nil {
		return nil, err
	}
	tf.pendingStart, tf.readPos = tf.offset, tf.offset
	slog.Info("tailing durably", "path", path, "type", t.logType, "offset", tf.offset)
	return tf, nil
}

// movedCursor finds the committed cursor of identity under another in-scope name.
func (t *durableTail) movedCursor(f *os.File, identity, key string) (evidence.Cursor, bool) {
	for source, c := range t.j.Cursors() {
		if source == key || c.Identity != identity || !strings.HasPrefix(source, fileSourcePrefix) {
			continue
		}
		if !sameContent(f, c.Bookmark) { // a reused identity, not the same file
			continue
		}
		if !t.inScope(strings.TrimPrefix(source, fileSourcePrefix)) {
			continue
		}
		if _, tracked := t.files[source]; tracked {
			continue
		}
		return c, true
	}
	return evidence.Cursor{}, false
}

// identityInScope reports whether identity is still reachable under a
// configured name other than key (so its unread bytes are not lost).
func (t *durableTail) identityInScope(identity, key string) bool {
	if !t.glob {
		return false
	}
	for _, path := range t.matches() {
		if fileSourcePrefix+path == key {
			continue
		}
		if id, err := pathIdentity(path); err == nil && id == identity {
			return true
		}
	}
	return false
}

func pathIdentity(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return fileIdentity(f)
}

// fresh starts a new generation of tf at offset and commits it as a baseline.
func (t *durableTail) fresh(tf *trackedFile, offset int64) error {
	tf.generation, tf.offset = newGeneration(), offset
	tf.fingerprint, tf.fingerprintLen = "", 0
	return t.baseline(tf)
}

func (t *durableTail) baseline(tf *trackedFile) error {
	c := t.cursor(tf, tf.offset)
	return t.control(func() error { return t.j.SaveBaseline(t.ctx, c) })
}

// cursor is tf's committed position at offset. Bookmark carries a fingerprint
// of the file's first bytes (up to fingerprintBytes), so a resume can tell the
// same file from a new one that reuses its inode or file index.
func (t *durableTail) cursor(tf *trackedFile, offset int64) evidence.Cursor {
	if tf.fingerprintLen < fingerprintBytes && offset > tf.fingerprintLen {
		if fp := fingerprint(tf.f, offset); fp != "" {
			tf.fingerprint, tf.fingerprintLen = fp, fingerprintLen(fp)
		}
	}
	return evidence.Cursor{Source: tf.key, Generation: tf.generation, Identity: tf.identity,
		Offset: offset, Bookmark: tf.fingerprint}
}

const fingerprintBytes = 256

// fingerprint hashes the first min(offset, fingerprintBytes) bytes of f.
func fingerprint(f *os.File, offset int64) string {
	n := offset
	if n > fingerprintBytes {
		n = fingerprintBytes
	}
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("fp:%d:%s", n, hex.EncodeToString(sum[:16]))
}

func fingerprintLen(bookmark string) int64 {
	var n int64
	var hash string
	if _, err := fmt.Sscanf(bookmark, "fp:%d:%s", &n, &hash); err != nil {
		return 0
	}
	return n
}

// sameContent reports whether f starts with the bytes bookmark fingerprinted.
// Cursors without a fingerprint (nothing read yet) match any file.
func sameContent(f *os.File, bookmark string) bool {
	n := fingerprintLen(bookmark)
	if n == 0 {
		return bookmark == "" || !strings.HasPrefix(bookmark, "fp:")
	}
	return fingerprint(f, n) == bookmark
}

func (t *durableTail) gap() error {
	if err := t.control(func() error { return t.j.RecordLoss(t.ctx, t.health, "rotation_gap", 0, true) }); err != nil {
		return err
	}
	t.state = "degraded"
	slog.Warn("log source gap: unread bytes may be lost", "path", t.path)
	return nil
}

// step reads one file and admits its complete lines. It reports whether it
// made progress; at EOF it handles truncation and rotation.
func (t *durableTail) step(tf *trackedFile) (bool, error) {
	progressed := false
	for budget := passBudget; budget > 0; {
		n, err := tf.f.Read(t.scratch)
		if n > 0 {
			progressed = true
			budget -= n
			tf.readPos += int64(n)
			tf.pending = append(tf.pending, t.scratch[:n]...)
			if err := t.lines(tf); err != nil {
				return progressed, err
			}
		}
		if err == io.EOF || (err == nil && n == 0) {
			return progressed, t.atEOF(tf)
		}
		if err != nil {
			slog.Error("reading log file", "path", tf.path, "err", err)
			t.setState("unavailable", "read_error")
			t.untrack(tf) // rediscovered later from its committed cursor
			return progressed, nil
		}
	}
	return progressed, nil
}

// lines admits every complete line in pending, oldest first.
func (t *durableTail) lines(tf *trackedFile) error {
	for {
		idx := bytes.IndexByte(tf.pending, '\n')
		if idx < 0 {
			if !tf.discarding && len(tf.pending) > t.maxLine {
				tf.discarding = true // keep memory bounded until the line ends
			}
			if tf.discarding {
				tf.pendingStart += int64(len(tf.pending))
				tf.pending = tf.pending[:0]
			}
			break
		}
		end := tf.pendingStart + int64(idx) + 1
		line := bytes.TrimRight(tf.pending[:idx], "\r")
		var err error
		switch {
		case tf.discarding || len(line) > t.maxLine:
			tf.discarding = false
			err = t.oversize(tf, end)
		case len(line) > 0:
			err = t.admit(tf, string(line), end)
		}
		if err != nil {
			return err
		}
		tf.pending = tf.pending[idx+1:]
		tf.pendingStart = end
	}
	if cap(tf.pending) > 2*readChunk && len(tf.pending) < readChunk { // release a grown buffer
		tf.pending = append([]byte(nil), tf.pending...)
	}
	return nil
}

// admit submits one line with the cursor just past it, retrying the same
// draft under disk pressure; the cursor only moves after durable admission.
func (t *durableTail) admit(tf *trackedFile, line string, end int64) error {
	c := t.cursor(tf, end)
	draft := evidence.Draft{LogType: t.logType, Location: tf.path, RawMessage: line, Cursor: &c}
	err := t.retry(func() error {
		_, err := t.sink.Submit(t.ctx, draft)
		return err
	})
	if errors.Is(err, evidence.ErrOversize) { // the encoded event is over the limit
		return t.oversize(tf, end)
	}
	if err != nil {
		return err
	}
	tf.offset = end
	return nil
}

// oversize counts a line over the event limit, then commits its end offset, so
// a restart neither loops on it nor skips it silently. A crash in between can
// count it twice; it is never lost from the counters.
func (t *durableTail) oversize(tf *trackedFile, end int64) error {
	if err := t.control(func() error { return t.j.RecordLoss(t.ctx, t.health, "oversize", 1, false) }); err != nil {
		return err
	}
	t.state = "degraded"
	slog.Warn("log line over the event size limit skipped", "path", tf.path, "end_offset", end)
	tf.offset = end
	return t.baseline(tf)
}

// control runs a journal write, waiting out disk pressure.
func (t *durableTail) control(write func() error) error { return t.retry(write) }

// retry repeats write while the journal is full or failing. It pauses the
// source (visible in health) and stops when ctx ends.
func (t *durableTail) retry(write func() error) error {
	wait := 100 * time.Millisecond
	for {
		err := write()
		switch {
		case err == nil:
			if t.state == "paused" || t.state == "unavailable" || t.state == "" {
				t.setState("healthy", "")
			}
			return nil
		case errors.Is(err, evidence.ErrOversize), errors.Is(err, evidence.ErrPublisherStopped),
			errors.Is(err, evidence.ErrIdentityMismatch), errors.Is(err, evidence.ErrInvalidControl):
			return err
		case t.ctx.Err() != nil:
			return t.ctx.Err()
		}
		reason := "storage_failure"
		if errors.Is(err, evidence.ErrFull) {
			reason = "capacity"
		}
		if t.state != "paused" {
			slog.Warn("log source paused", "path", t.path, "reason", reason, "err", err)
		}
		t.setState("paused", reason)
		if !sleepCtx(t.ctx, wait) {
			return t.ctx.Err()
		}
		if wait *= 2; wait > maxPressureWait {
			wait = maxPressureWait
		}
	}
}

// atEOF detects copytruncate and rotation once everything readable was read.
func (t *durableTail) atEOF(tf *trackedFile) error {
	fi, err := tf.f.Stat()
	if err == nil && fi.Size() < tf.readPos {
		// copytruncate: bytes written after our last read and before the
		// truncation are gone, and a partial line can never complete
		if err := t.gap(); err != nil {
			return err
		}
		if _, err := tf.f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		tf.pending, tf.discarding, tf.pendingStart, tf.readPos = tf.pending[:0], false, 0, 0
		return t.fresh(tf, 0)
	}
	current, err := pathIdentity(tf.path)
	if err == nil && current == tf.identity {
		return nil
	}
	// The name now points to another file or nothing. Read what the writer
	// added between our last read and the rename, then the open file is
	// drained and its last unterminated line is final.
	for {
		n, err := tf.f.Read(t.scratch)
		if n > 0 {
			tf.readPos += int64(n)
			tf.pending = append(tf.pending, t.scratch[:n]...)
			if err := t.lines(tf); err != nil {
				return err
			}
		}
		if err != nil || n == 0 {
			break
		}
	}
	if line := bytes.TrimRight(tf.pending, "\r\n"); len(line) > 0 {
		var err error
		if tf.discarding || len(line) > t.maxLine {
			err = t.oversize(tf, tf.readPos)
		} else {
			err = t.admit(tf, string(line), tf.readPos)
		}
		if err != nil {
			return err
		}
	}
	slog.Info("log file rotated, drained", "path", tf.path)
	if !t.identityInScope(tf.identity, tf.key) {
		// nobody else will continue this identity: mark the name drained so the
		// next file here starts at zero without reporting a gap
		drained := evidence.Cursor{Source: tf.key, Generation: tf.generation, Empty: true}
		if err := t.control(func() error { return t.j.SaveBaseline(t.ctx, drained) }); err != nil {
			return err
		}
	}
	t.untrack(tf)
	t.lastDiscover = time.Time{} // pick up the replacement right away
	return nil
}

func (t *durableTail) untrack(tf *trackedFile) {
	tf.f.Close()
	delete(t.files, tf.key)
}

func (t *durableTail) setState(state, reason string) {
	if t.state == state {
		return
	}
	if reason == "" {
		reason = state // the journal requires a reason
	}
	if err := t.j.SetSourceState(t.ctx, t.health, state, reason); err != nil {
		if t.ctx.Err() == nil {
			slog.Warn("recording log source health", "path", t.path, "err", err)
		}
		return
	}
	t.state = state
}

func newGeneration() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
