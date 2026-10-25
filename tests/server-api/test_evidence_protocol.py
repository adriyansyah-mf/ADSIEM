"""Wire contract shared with the Go journal, independent of PostgreSQL."""
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import schemas

FIXTURE = Path(__file__).parents[1] / "fixtures/evidence-v2.json"


def envelope(**changes):
    assert hasattr(schemas, "EvidenceEnvelope"), "v2 envelope schema is not implemented"
    return schemas.EvidenceEnvelope.model_validate(json.loads(FIXTURE.read_text()) | changes)


def test_shared_go_fixture_preserves_unicode_nul_and_nanoseconds():
    body = envelope()
    expected = ('{"agent_id":"11111111-1111-4111-8111-111111111111",'
                '"collected_at":"2026-10-21T01:02:03.123456789Z",'
                '"cursor":{"generation":"one","identity":"inode","offset":42,"source":"file"},'
                '"event_id":"22222222-2222-4222-8222-222222222222",'
                '"hostname":"host","location":"/logs","log_type":"syslog",'
                '"protocol_version":2,"raw_message":"a\\n\\u0000b 世界"}')
    assert body.canonical_json() == expected
    assert body.digest() == hashlib.sha256(expected.encode()).hexdigest()
    assert body.encoded_size == len(expected.encode())


def test_uuid_and_timestamp_normalization_does_not_change_digest():
    original = envelope(event_id="abcdefab-cdef-4abc-8def-abcdefabcdef")
    equivalent = envelope(event_id="ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF",
                          collected_at="2026-10-21T08:02:03.123456789+07:00")
    assert original.digest() == equivalent.digest()
    assert envelope(collected_at="2026-10-21T01:02:03.123456780Z").digest() == envelope(
        collected_at="2026-10-21T01:02:03.12345678Z").digest()


@pytest.mark.parametrize("changes", [
    {"collected_at": "2026-10-21T01:02:03.123456788Z"},
    {"hostname": "different"}, {"log_type": "winevent"}, {"location": "other"},
    {"raw_message": "a\\n\\u0000b 世界"}, {"legacy_import": True},
    {"cursor": {"source": "file", "generation": "two", "identity": "inode", "offset": 42}},
    {"cursor": {"source": "file", "generation": "one", "identity": "inode", "offset": 43}},
    {"cursor": {"source": "file", "generation": "one", "identity": "inode", "bookmark": "changed"}},
    {"cursor": {"source": "file", "generation": "one", "identity": "inode", "empty": True}},
])
def test_every_immutable_change_affects_digest(changes):
    assert envelope().digest() != envelope(**changes).digest()


def test_go_escaping_and_omitted_cursor_fields_define_encoded_size():
    body = envelope(raw_message="<>&\u2028\u2029世界", cursor={
        "source": "file", "generation": "one", "identity": "inode", "offset": 0,
        "bookmark": "", "empty": False,
    }, legacy_import=False)
    canonical = json.loads(body.canonical_json())
    assert canonical["cursor"] == {"source": "file", "generation": "one", "identity": "inode"}
    assert "legacy_import" not in canonical
    # Go adds five bytes for each escaped character, including 3-byte Unicode separators.
    assert body.encoded_size == len(body.canonical_json().encode()) + 15 + 6


@pytest.mark.parametrize("changes", [
    {"protocol_version": 3}, {"protocol_version": True}, {"protocol_version": 2.0},
    {"collected_at": "0001-01-01T00:00:00+23:00"},
    {"collected_at": "9999-12-31T23:59:59-23:00"},
    {"collected_at": "2026-10-21T01:02:03.1234567891Z"},
    {"collected_at": "2026-10-21T01:02:03"}, {"collected_at": "not-a-time"},
    {"agent_id": "00000000-0000-0000-0000-000000000000"},
    {"raw_message": "\ud800"}, {"hostname": "\udfff"},
    {"group_id": "spoofed"}, {"token": "secret"},
])
def test_invalid_wire_values_fail_validation(changes):
    with pytest.raises(ValidationError):
        envelope(**changes)
