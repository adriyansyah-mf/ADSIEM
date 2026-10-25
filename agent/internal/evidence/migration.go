package evidence

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// legacySourcePrefix names the cursor of an imported legacy spill:
// legacy-spill:<path>. Its bookmark fingerprints the spill's first bytes.
const legacySourcePrefix = "legacy-spill:"

const legacyFingerprintBytes = 4096

// legacyHealthSource is the import's health entry (one spill per agent; a
// path-derived name could exceed the 256-byte health name limit).
const legacyHealthSource = "legacy-spill"

// ErrMigrationBlocked: the journal is full; the import keeps its progress and
// resumes once delivery frees space.
var ErrMigrationBlocked = errors.New("evidence: legacy spill import blocked: journal capacity exhausted")

// afterImportRecord is a test hook called after each record is flushed.
var afterImportRecord func()

// ImportLegacy copies the legacy disk spill (buffer.Spill: one entry per line,
// "logType\x00location\x00raw", newlines in messages stored as \x1e) into the
// journal, run by the single writer before producers start.
//
// The spill is never modified: completion is a durable marker in the journal.
// Each imported record carries the import cursor (spill fingerprint, byte
// offset after its line) in the same flush, so an interrupted import resumes at
// the last committed line. Event IDs derive from the agent, the spill
// fingerprint and the line offset, so a line keeps its identity across reruns.
// Imported events are labelled legacy_import, collected now: the spill kept no
// original IDs or times and may already contain duplicates. Entries over the
// event limit are counted as legacy_import loss (the original line stays in the
// spill). A full journal returns ErrMigrationBlocked with progress kept.
func ImportLegacy(ctx context.Context, j *Journal, path, agentID, hostname string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open legacy spill: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	if size == 0 {
		return nil
	}
	source := legacySourcePrefix + path
	start, generation, fp := int64(0), "", ""
	if saved, ok := j.Cursor(source); ok && saved.Bookmark != "" && sameLegacy(f, saved.Bookmark) {
		if saved.Empty && saved.Offset >= size {
			return nil // completed
		}
		start, generation, fp = saved.Offset, saved.Generation, saved.Bookmark
	} else {
		// first import, or another file substituted at the path
		if fp, err = legacyFingerprint(f, size); err != nil {
			return err
		}
		generation = randomGeneration()
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}

	r := bufio.NewReaderSize(f, 64<<10)
	offset := start
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, n, oversized, err := readLegacyLine(r, j.options.MaxEventBytes)
		if err != nil {
			return fmt.Errorf("read legacy spill: %w", err)
		}
		if n == 0 {
			break // EOF
		}
		end := offset + int64(n)
		cursor := Cursor{Source: source, Generation: generation, Identity: "legacy-spill", Offset: end, Bookmark: fp}
		if strings.TrimSpace(line) != "" || oversized {
			if !oversized {
				err = j.Append(ctx, legacyEnvelope(j, agentID, hostname, line, cursor))
			}
			if oversized || errors.Is(err, ErrOversize) {
				err = j.RecordLoss(ctx, legacyHealthSource, "legacy_import", 1, false)
				if err == nil {
					err = j.SaveBaseline(ctx, cursor)
				}
			}
			if errors.Is(err, ErrFull) {
				_ = j.SetSourceState(ctx, legacyHealthSource, "paused", "migration_blocked")
				return fmt.Errorf("%w (imported up to byte %d of %d)", ErrMigrationBlocked, offset, size)
			}
			if err != nil {
				return err
			}
			if afterImportRecord != nil {
				afterImportRecord()
			}
		}
		offset = end
	}
	done := Cursor{Source: source, Generation: generation, Identity: "legacy-spill", Offset: offset, Bookmark: fp, Empty: true}
	if err := j.SaveBaseline(ctx, done); err != nil {
		if errors.Is(err, ErrFull) {
			_ = j.SetSourceState(ctx, legacyHealthSource, "paused", "migration_blocked")
			return fmt.Errorf("%w (completion marker)", ErrMigrationBlocked)
		}
		return err
	}
	return j.SetSourceState(ctx, legacyHealthSource, "healthy", "imported")
}

// ImportComplete reports whether path's current content was fully imported.
func ImportComplete(j *Journal, path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.Size() == 0 {
		return true
	}
	saved, ok := j.Cursor(legacySourcePrefix + path)
	return ok && saved.Empty && saved.Offset >= fi.Size() && sameLegacy(f, saved.Bookmark)
}

// readLegacyLine reads one line with bounded memory: past limit bytes the
// line is consumed but not kept (oversized). n is the bytes consumed,
// including the newline; 0 at EOF.
func readLegacyLine(r *bufio.Reader, limit int) (line string, n int, oversized bool, err error) {
	var kept []byte
	for {
		chunk, err := r.ReadSlice('\n')
		n += len(chunk)
		if !oversized {
			kept = append(kept, chunk...)
			if len(kept) > limit+1 {
				oversized, kept = true, nil
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			// a final line without newline: the old writer was cut off mid-write
			return strings.TrimRight(string(kept), "\n"), n, oversized, nil
		case err != nil:
			return "", n, oversized, err
		}
		return strings.TrimRight(string(kept), "\n"), n, oversized, nil
	}
}

func legacyEnvelope(j *Journal, agentID, hostname, line string, cursor Cursor) Envelope {
	logType, location, raw := "unknown", "", line
	switch parts := strings.SplitN(line, "\x00", 3); len(parts) {
	case 3:
		logType, location, raw = parts[0], parts[1], parts[2]
	case 2:
		logType, raw = parts[0], parts[1]
	}
	c := cursor
	return Envelope{
		ProtocolVersion: 2, EventID: legacyEventID(agentID, cursor.Bookmark, cursor.Offset), AgentID: agentID,
		CollectedAt: j.now().UTC(), Hostname: hostname, LogType: logType, Location: location,
		RawMessage: strings.ReplaceAll(raw, "\x1e", "\n"), Cursor: &c, LegacyImport: true,
	}
}

// legacyEventID is a version-5-shaped UUID from the agent, spill fingerprint
// and line end offset: stable across interrupted and repeated imports.
func legacyEventID(agentID, fingerprint string, offset int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", agentID, fingerprint, offset)))
	id := sum[:16]
	id[6] = (id[6] & 0x0f) | 0x50
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

// legacyFingerprint hashes the spill's first min(size, 4096) bytes.
func legacyFingerprint(f *os.File, size int64) (string, error) {
	n := min(size, legacyFingerprintBytes)
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil {
		return "", fmt.Errorf("fingerprint legacy spill: %w", err)
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("fp:%d:%s", n, hex.EncodeToString(sum[:16])), nil
}

// sameLegacy reports whether f still starts with the fingerprinted bytes.
func sameLegacy(f *os.File, bookmark string) bool {
	var n int64
	var hash string
	if _, err := fmt.Sscanf(bookmark, "fp:%d:%s", &n, &hash); err != nil || n <= 0 {
		return false
	}
	got, err := legacyFingerprint(f, n)
	return err == nil && got == bookmark
}

func randomGeneration() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
