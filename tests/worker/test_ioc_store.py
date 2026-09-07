from __future__ import annotations

import uuid

import pytest

from worker.ioc_store import (
    VALID_ENTITY_TYPES,
    link_ioc,
    record_enrichment_iocs,
    upsert_ioc_observation,
    verdict_from_confidence,
)


class _FakeResult:
    def __init__(self, scalar=None):
        self._scalar = scalar

    def scalar_one(self):
        return self._scalar


class _FakeSession:
    def __init__(self, scalars: list | None = None) -> None:
        self._scalars = list(scalars or [])
        self.calls: list[tuple[str, dict]] = []
        self.commits = 0

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params or {}))
        is_upsert = "INSERT INTO ioc_observations" in str(stmt)
        scalar = self._scalars.pop(0) if is_upsert and self._scalars else None
        return _FakeResult(scalar)

    async def commit(self) -> None:
        self.commits += 1


class _Ioc:
    def __init__(self, value: str, type_) -> None:
        self.value = value
        self.type = type_


class _Reputation:
    def __init__(self, ioc_value: str, score: float) -> None:
        self.ioc_value = ioc_value
        self.score = score


def test_verdict_from_confidence_thresholds() -> None:
    assert verdict_from_confidence(0.9) == "malicious"
    assert verdict_from_confidence(0.7) == "malicious"
    assert verdict_from_confidence(0.69) == "suspicious"
    assert verdict_from_confidence(0.3) == "suspicious"
    assert verdict_from_confidence(0.1) == "unknown"


@pytest.mark.asyncio
async def test_upsert_ioc_observation_returns_id_from_scalar_one() -> None:
    ioc_id = uuid.uuid4()
    session = _FakeSession(scalars=[ioc_id])

    result = await upsert_ioc_observation(
        session, group_id="blue", indicator="1.2.3.4", ioc_type="ipv4",
        confidence=0.8, verdict="malicious", source="ti_enrichment",
    )

    assert result == ioc_id
    assert len(session.calls) == 1
    _, params = session.calls[0]
    assert params["group_id"] == "blue"
    assert params["indicator"] == "1.2.3.4"
    assert params["confidence"] == 0.8
    assert params["id"]  # explicit id required: no DB-side default on this column


@pytest.mark.asyncio
async def test_link_ioc_rejects_invalid_entity_type_without_executing() -> None:
    session = _FakeSession()
    with pytest.raises(ValueError, match="invalid entity_type"):
        await link_ioc(session, ioc_id=uuid.uuid4(), group_id="blue", entity_type="widget", entity_id="x")
    assert session.calls == []


@pytest.mark.asyncio
async def test_link_ioc_accepts_every_valid_entity_type() -> None:
    for entity_type in VALID_ENTITY_TYPES:
        session = _FakeSession()
        await link_ioc(session, ioc_id=uuid.uuid4(), group_id="blue", entity_type=entity_type, entity_id="x")
        assert len(session.calls) == 1
        assert session.calls[0][1]["id"]  # explicit id required: no DB-side default


@pytest.mark.asyncio
async def test_record_enrichment_iocs_persists_and_links_each_indicator() -> None:
    ioc_ids = [uuid.uuid4(), uuid.uuid4()]
    session = _FakeSession(scalars=[ioc_ids[0], ioc_ids[1]])
    iocs = [_Ioc("1.2.3.4", "ipv4"), _Ioc("evil.test", "domain")]
    reputation = [_Reputation("1.2.3.4", 0.9), _Reputation("evil.test", 0.2)]

    result_ids = await record_enrichment_iocs(
        session, group_id="blue", alert_id="alert-1", iocs=iocs, reputation=reputation,
    )

    assert result_ids == ioc_ids
    # 2 upserts + 2 links
    assert len(session.calls) == 4
    assert session.commits == 1
    upsert_calls = [c for c in session.calls if "INSERT INTO ioc_observations" in c[0]]
    assert upsert_calls[0][1]["verdict"] == "malicious"
    assert upsert_calls[1][1]["verdict"] == "unknown"
    link_calls = [c for c in session.calls if "INSERT INTO ioc_links" in c[0]]
    assert all(c[1]["entity_id"] == "alert-1" for c in link_calls)


@pytest.mark.asyncio
async def test_record_enrichment_iocs_skips_linking_when_no_alert_id() -> None:
    session = _FakeSession(scalars=[uuid.uuid4()])
    iocs = [_Ioc("1.2.3.4", "ipv4")]

    await record_enrichment_iocs(session, group_id="blue", alert_id=None, iocs=iocs, reputation=[])

    link_calls = [c for c in session.calls if "INSERT INTO ioc_links" in c[0]]
    assert link_calls == []
    assert session.commits == 1


@pytest.mark.asyncio
async def test_record_enrichment_iocs_handles_enum_valued_ioc_type() -> None:
    class _EnumType:
        value = "ipv4"

    session = _FakeSession(scalars=[uuid.uuid4()])
    iocs = [_Ioc("1.2.3.4", _EnumType())]

    await record_enrichment_iocs(session, group_id="blue", alert_id=None, iocs=iocs, reputation=[])

    _, params = session.calls[0]
    assert params["ioc_type"] == "ipv4"
