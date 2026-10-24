package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"
)

var (
	ErrFull             = errors.New("evidence: disk budget exhausted")
	ErrLocked           = errors.New("evidence: journal already owned")
	ErrCorrupt          = errors.New("evidence: corrupt journal")
	ErrIdentityMismatch = errors.New("evidence: agent identity mismatch")
	ErrOversize         = errors.New("evidence: record exceeds event or segment limit")
	ErrUnsupported      = errors.New("evidence: unsupported durable storage")
)

type storage interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type segment struct {
	name     string
	sequence uint64
	size     int64
}

// Journal serializes admissions and keeps payloads on disk. Successful admission
// means the complete frame and its source cursor have reached the same flush.
// It assumes local storage honoring flushes and stable, trusted path ancestors.
type Journal struct {
	mu         sync.Mutex
	options    Options
	dir        *storageDir
	lock       *os.File
	writer     storage
	segments   []segment
	cursors    map[string]Cursor
	used       int64
	poison     error
	closed     bool
	checkpoint checkpoint
	sequence   uint64
	generation uint64
	now        func() time.Time
	fault      func(operation, name string) error
	storageGap bool
	capacity   bool
	bridgeLoss bridgeLoss
	index      eventIndex // event ID -> retained occurrences (index.go)
	// peekFrom: every record before it was acknowledged or held/quarantined
	// at the last Peek; reset when something can make an older record
	// deliverable again (release, compaction).
	peekFrom eventPosition
}

type journalDependencies struct {
	now   func() time.Time
	fault func(operation, name string) error
}

func Open(o Options) (*Journal, error) {
	return openWithDependencies(o, journalDependencies{now: time.Now})
}

func openWithDependencies(o Options, deps journalDependencies) (_ *Journal, err error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateAgentID(o.AgentID); err != nil {
		return nil, err
	}
	if uint64(o.MaxEventBytes) > math.MaxUint32 || o.SegmentBytes <= segmentHeaderSize+frameHeaderSize {
		return nil, ErrInvalidOptions
	}
	d, err := openStorageDir(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("open evidence directory: %w", err)
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	j := &Journal{options: o, dir: d, cursors: make(map[string]Cursor), checkpoint: emptyCheckpoint(o.AgentID), now: deps.now, fault: deps.fault}
	defer func() {
		if err != nil {
			err = errors.Join(err, j.Close())
		}
	}()
	j.lock, err = d.lock()
	if err != nil {
		return nil, fmt.Errorf("acquire journal: %w", err)
	}
	if err = j.recover(); err != nil {
		return nil, fmt.Errorf("recover journal: %w", err)
	}
	if err = j.rebuildIndex(context.Background()); err != nil {
		return nil, fmt.Errorf("index journal: %w", err)
	}
	return j, nil
}

func (j *Journal) Append(ctx context.Context, e Envelope) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e.AgentID != j.options.AgentID {
		return ErrIdentityMismatch
	}
	if e.ProtocolVersion != 2 {
		return fmt.Errorf("event protocol: %w", ErrCorrupt)
	}
	if err := ValidateAgentID(e.EventID); err != nil {
		return err
	}
	if e.Cursor != nil {
		if e.Cursor.Source == "" {
			return ErrInvalidControl
		}
		c := *e.Cursor
		e.Cursor = &c
	}
	if err := j.checkDuplicate(ctx, e); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	if err := j.admit(ctx, frameEvent, b); err != nil {
		return err
	}
	last := j.segments[len(j.segments)-1]
	j.indexAdd(e.EventID, eventPosition{last.sequence, last.size - int64(frameHeaderSize) - int64(len(b)), last.size})
	if e.Cursor != nil {
		j.cursors[e.Cursor.Source] = *e.Cursor
	}
	return nil
}

func (j *Journal) SaveBaseline(ctx context.Context, c Cursor) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if c.Source == "" {
		return fmt.Errorf("empty baseline source: %w", ErrInvalidControl)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	if err := j.admit(ctx, frameBaseline, b); err != nil {
		return err
	}
	j.cursors[c.Source] = c
	return nil
}

func (j *Journal) admit(ctx context.Context, kind byte, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.closed {
		return os.ErrClosed
	}
	if j.poison != nil {
		return fmt.Errorf("journal requires reopen: %w", j.poison)
	}
	size := int64(frameHeaderSize) + int64(len(payload))
	if len(payload) > j.options.MaxEventBytes || size > j.options.SegmentBytes-segmentHeaderSize {
		return ErrOversize
	}
	rotate := len(j.segments) == 0 || j.segments[len(j.segments)-1].size+size > j.options.SegmentBytes
	additional := size
	if rotate {
		additional += segmentHeaderSize
	}
	limit := j.options.MaxBytes
	if kind == frameEvent {
		limit -= j.options.ReservedBytes
	}
	if additional > limit-j.used {
		j.capacity = true
		return ErrFull
	}
	if rotate {
		if err := j.newSegment(); err != nil {
			return j.storageFailed(err)
		}
	}
	if err := writeFull(j.writer, encodeFrame(kind, payload)); err != nil {
		return j.storageFailed(err)
	}
	if err := j.writer.Sync(); err != nil {
		return j.storageFailed(fmt.Errorf("flush record: %w", err))
	}
	j.segments[len(j.segments)-1].size += size
	j.used += size
	j.capacity = false
	return nil
}

func writeFull(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func (j *Journal) Cursor(source string) (Cursor, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	c, ok := j.cursors[source]
	return c, ok
}

// Cursors returns a copy of every committed source cursor. Collectors use it to
// find a rotated file identity under another name in their configured scope.
func (j *Journal) Cursors() map[string]Cursor {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make(map[string]Cursor, len(j.cursors))
	for key, value := range j.cursors {
		out[key] = value
	}
	return out
}

// MaxEventBytes is the largest encoded event the journal admits. Collectors
// bound their per-source line buffers with it.
func (j *Journal) MaxEventBytes() int { return j.options.MaxEventBytes }

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	var errs []error
	if j.writer != nil {
		errs = append(errs, j.writer.Close())
	}
	if j.lock != nil {
		errs = append(errs, j.lock.Close())
	}
	if j.dir != nil {
		errs = append(errs, j.dir.close())
	}
	return errors.Join(errs...)
}
