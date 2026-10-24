package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidAgentID = errors.New("evidence: invalid agent UUID")

type Cursor struct {
	Source     string `json:"source"`
	Generation string `json:"generation"`
	Identity   string `json:"identity"`
	Offset     int64  `json:"offset,omitempty"`
	Bookmark   string `json:"bookmark,omitempty"`
	Empty      bool   `json:"empty,omitempty"`
}

type Draft struct {
	LogType, Location, RawMessage string
	Cursor                        *Cursor
}

// Envelope is a collected snapshot. Callers must treat it as immutable.
// Credentials belong to transport headers, never the journal record.
type Envelope struct {
	ProtocolVersion int       `json:"protocol_version"`
	EventID         string    `json:"event_id"`
	AgentID         string    `json:"agent_id"`
	CollectedAt     time.Time `json:"collected_at"`
	Hostname        string    `json:"hostname"`
	LogType         string    `json:"log_type"`
	Location        string    `json:"location"`
	RawMessage      string    `json:"raw_message"`
	Cursor          *Cursor   `json:"cursor,omitempty"`
	LegacyImport    bool      `json:"legacy_import,omitempty"`
}

func ValidateAgentID(id string) error {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return ErrInvalidAgentID
	}
	compact := id[:8] + id[9:13] + id[14:18] + id[19:23] + id[24:]
	var decoded [16]byte
	if _, err := hex.Decode(decoded[:], []byte(compact)); err != nil {
		return fmt.Errorf("%w: malformed hex", ErrInvalidAgentID)
	}
	if decoded == [16]byte{} {
		return ErrInvalidAgentID
	}
	return nil
}

// NewEnvelope preserves the supplied timestamp and draft without normalization.
// Empty drafts and a zero timestamp are representable; ingestion validates its
// own payload requirements separately. The optional cursor is copied by value.
func NewEnvelope(agentID, hostname string, d Draft, now time.Time) (Envelope, error) {
	if err := ValidateAgentID(agentID); err != nil {
		return Envelope{}, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Envelope{}, fmt.Errorf("generate event UUID: %w", err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	eventID := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	var cursor *Cursor
	if d.Cursor != nil {
		snapshot := *d.Cursor
		cursor = &snapshot
	}
	return Envelope{ProtocolVersion: 2, EventID: eventID, AgentID: agentID, CollectedAt: now, Hostname: hostname, LogType: d.LogType, Location: d.Location, RawMessage: d.RawMessage, Cursor: cursor}, nil
}
