package evidence

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testAgentID = "11111111-1111-4111-8111-111111111111"

func TestEnvelopeRoundTrip(t *testing.T) {
	// Given: payload bytes and cursor must survive encoding without aliasing.
	at := time.Date(2026, 10, 21, 1, 2, 3, 123456789, time.UTC)
	cursor := Cursor{Source: "file", Generation: "one", Identity: "inode", Offset: 42}
	e, err := NewEnvelope(testAgentID, "host", Draft{LogType: "syslog", Location: "/logs", RawMessage: "a\n\x00b 世界", Cursor: &cursor}, at)
	if err != nil {
		t.Fatal(err)
	}
	cursor.Offset = 99
	// When
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got Envelope
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	// Then
	if !reflect.DeepEqual(e, got) || got.Cursor.Offset != 42 || got.ProtocolVersion != 2 {
		t.Fatalf("envelope changed: %+v", got)
	}
	if strings.Contains(string(b), "token") {
		t.Fatal("credential field serialized")
	}
}

func TestEnvelopeRandomUUIDs(t *testing.T) {
	// Given
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		// When
		e, err := NewEnvelope(testAgentID, "host", Draft{}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// Then
		if len(e.EventID) != 36 || e.EventID[14] != '4' || !strings.ContainsRune("89ab", rune(e.EventID[19])) || seen[e.EventID] {
			t.Fatalf("invalid/reused UUID: %s", e.EventID)
		}
		seen[e.EventID] = true
	}
}

func TestEnvelopeInvalidAgentID(t *testing.T) {
	for _, id := range []string{"", "invalid", "11111111-1111-4111-8111-11111111111z"} {
		// When
		_, err := NewEnvelope(id, "host", Draft{}, time.Now())
		// Then
		if err == nil {
			t.Fatalf("accepted agent ID %q", id)
		}
	}
}

func TestEnvelopeSharedFixture(t *testing.T) {
	// Given
	b, err := os.ReadFile("../../../tests/fixtures/evidence-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	// When
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	// Then
	if e.ProtocolVersion != 2 || e.AgentID != testAgentID || e.RawMessage != "a\n\x00b 世界" || e.CollectedAt.Nanosecond() != 123456789 {
		t.Fatalf("unexpected fixture: %+v", e)
	}
}

func TestEvidenceOptionsRejectInvalidBudgets(t *testing.T) {
	for _, o := range []Options{
		{Dir: "evidence", AgentID: testAgentID, MaxBytes: -1, SegmentBytes: 1, ReservedBytes: 1, MaxEventBytes: 1},
		{Dir: "evidence", AgentID: testAgentID, MaxBytes: 100, SegmentBytes: 91, ReservedBytes: 10, MaxEventBytes: 1},
		{Dir: "evidence", AgentID: testAgentID, MaxBytes: 100, SegmentBytes: 50, ReservedBytes: -1, MaxEventBytes: 1},
		{Dir: "evidence", AgentID: testAgentID, MaxBytes: 100, SegmentBytes: 50, ReservedBytes: 10, MaxEventBytes: -1},
		{Dir: "evidence", AgentID: "bad", MaxBytes: 100, SegmentBytes: 50, ReservedBytes: 10, MaxEventBytes: 1},
	} {
		// When / Then
		if err := o.Validate(); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}
