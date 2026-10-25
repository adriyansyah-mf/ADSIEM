package evidence

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
)

const commitSize = 64

func generationName(prefix string, generation uint64) string {
	return fmt.Sprintf("%s-%020d.evj", prefix, generation)
}

// publicationStep is a package-private deterministic I/O seam. Production has
// no fault environment variables; tests inject only named boundary failures.
func (j *Journal) publicationStep(operation, name string) error {
	if j.fault != nil {
		return j.fault(operation, name)
	}
	return nil
}

func (j *Journal) publish(ctx context.Context, c checkpoint) error {
	if err := j.ready(ctx); err != nil {
		return err
	}
	if j.generation == ^uint64(0) {
		j.capacity = true
		return ErrFull
	}
	c.Generation = j.generation + 1
	payload, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	if uint64(len(payload)) > math.MaxUint32 {
		j.capacity = true
		return ErrFull
	}
	frame := encodeFrame(3, payload)
	additional := int64(len(frame) + commitSize)
	// Leave equal space for a successor generation while data is at its limit.
	// Refuse before touching the namespace if control metadata cannot rotate.
	if additional > j.options.ReservedBytes/2 || additional > j.options.MaxBytes-j.used {
		j.capacity = true
		return ErrFull
	}
	checkpointName := generationName("checkpoint", c.Generation)
	manifestName := generationName("commit", c.Generation)
	if err := j.writeGenerationFile(checkpointName, frame); err != nil {
		return j.storageFailed(err)
	}
	manifest := make([]byte, commitSize)
	copy(manifest, "EVJCOM01")
	binary.LittleEndian.PutUint64(manifest[8:16], c.Generation)
	binary.LittleEndian.PutUint64(manifest[16:24], uint64(len(frame)))
	binary.LittleEndian.PutUint32(manifest[24:28], crc32.Checksum(frame, checksumTable))
	binary.LittleEndian.PutUint32(manifest[60:], crc32.Checksum(manifest[:60], checksumTable))
	if err := j.publicationStep("before-publication", manifestName); err != nil {
		return j.storageFailed(err)
	}
	if err := j.writeGenerationFile(manifestName, manifest); err != nil {
		return j.storageFailed(err)
	}
	if err := j.publicationStep("after-publication", manifestName); err != nil {
		return j.storageFailed(err)
	}
	j.checkpoint = c
	j.generation = c.Generation
	j.capacity = false
	if err := j.cleanGenerations(); err != nil {
		return j.storageFailed(err)
	}
	return nil
}

func (j *Journal) writeGenerationFile(name string, b []byte) (err error) {
	if err := j.publicationStep("before-create", name); err != nil {
		return err
	}
	f, err := j.dir.open(name, os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if err := j.publicationStep("after-create", name); err != nil {
		return err
	}
	if err := j.publicationStep("before-write", name); err != nil {
		return err
	}
	if err := writeFull(f, b); err != nil {
		return err
	}
	j.used += int64(len(b))
	if err := j.publicationStep("after-write", name); err != nil {
		return err
	}
	if err := j.publicationStep("before-file-sync", name); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := j.publicationStep("after-file-sync", name); err != nil {
		return err
	}
	if err := j.publicationStep("before-namespace-sync", name); err != nil {
		return err
	}
	if err := j.dir.sync(); err != nil {
		return err
	}
	return j.publicationStep("after-namespace-sync", name)
}

func (j *Journal) removeStateFile(name string) error {
	if err := j.publicationStep("before-remove", name); err != nil {
		return err
	}
	f, err := j.dir.open(name, os.O_RDONLY)
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	if err := errors.Join(statErr, f.Close()); err != nil {
		return err
	}
	if err := j.dir.remove(name); err != nil {
		return err
	}
	if err := j.publicationStep("after-remove", name); err != nil {
		return err
	}
	if err := j.publicationStep("before-delete-sync", name); err != nil {
		return err
	}
	if err := j.dir.sync(); err != nil {
		return err
	}
	j.used -= info.Size()
	return j.publicationStep("after-delete-sync", name)
}

func (j *Journal) cleanGenerations() error {
	names, err := j.dir.names()
	if err != nil {
		return err
	}
	// Remove obsolete commit markers before their snapshots, so no surviving
	// valid old marker can refer to a snapshot we deliberately removed.
	for _, prefix := range []string{"commit", "checkpoint"} {
		for _, name := range names {
			generation, ok := parseGeneration(name, prefix)
			if !ok || generation == j.checkpoint.Generation {
				continue
			}
			if err := j.removeStateFile(name); err != nil {
				return err
			}
		}
	}
	return nil
}
