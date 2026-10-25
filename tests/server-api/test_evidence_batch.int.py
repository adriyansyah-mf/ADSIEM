# tests/server-api/test_evidence_batch.int.py
"""POST /api/ingest/v2/logs accepts up to 500 envelopes in one transaction
and answers per event, in order: accepted / duplicate (same receipt) /
rejected (409 changed payload, 413 too large, 422 invalid) / retry (429 group
budget). Request-level failures (disabled, not durable, unapproved, another
agent's events, oversized body) still refuse the whole request."""
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest


def envelope(agent_id, **over):
    e = {"protocol_version": 2, "event_id": str(uuid4()), "agent_id": str(agent_id),
         "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
         "hostname": "blue-host", "log_type": "syslog", "location": "/var/log/syslog",
         "raw_message": "Oct 25 sshd: Failed password for root"}
    e.update(over)
    return e


@pytest.fixture
def enabled(evidence_api, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "EVIDENCE_INGEST_ENABLED", True)
    monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", 1 << 30)
    evidence_api.headers = {"X-Agent-Token": "blue-token"}
    return evidence_api


async def post(env, events, **extra):
    body = {"protocol_version": 2, "events": events, **extra}
    return await env.client.post("/api/ingest/v2/logs", json=body, headers=env.headers)


async def inbox_rows(env):
    from sqlalchemy import select
    from app.models import models
    async with env.sessions() as db:
        return (await db.execute(select(models.EvidenceInbox))).scalars().all()


async def test_batch_accepts_in_one_transaction_and_retries_are_duplicates(enabled):
    blue = enabled.agents["blue"]
    events = [envelope(blue) for _ in range(3)]
    r = await post(enabled, events)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["protocol_version"] == 2
    results = body["results"]
    assert [x["event_id"] for x in results] == [e["event_id"] for e in events]
    assert all(x["status"] == "accepted" for x in results)
    assert len({x["receipt_id"] for x in results}) == 3
    assert len(await inbox_rows(enabled)) == 3

    again = (await post(enabled, events)).json()["results"]  # the response was lost
    assert [x["status"] for x in again] == ["duplicate"] * 3
    assert [x["receipt_id"] for x in again] == [x["receipt_id"] for x in results]
    assert len(await inbox_rows(enabled)) == 3


async def test_per_event_rejections_do_not_fail_the_batch(enabled):
    blue = enabled.agents["blue"]
    stored = envelope(blue)
    await post(enabled, [stored])
    changed = {**stored, "raw_message": "tampered"}
    invalid = envelope(blue, collected_at="yesterday")
    huge = envelope(blue, raw_message="x" * (1 << 20))
    ok = envelope(blue)
    r = await post(enabled, [changed, invalid, ok, huge])
    assert r.status_code == 200, r.text
    results = r.json()["results"]
    assert [(x["status"], x.get("code")) for x in results] == [
        ("rejected", 409), ("rejected", 422), ("accepted", None), ("rejected", 413)]
    assert results[1]["event_id"] == invalid["event_id"]
    assert "raw_message" not in json.dumps(results) and "tampered" not in json.dumps(results)
    assert len(await inbox_rows(enabled)) == 2  # the original and the valid one


async def test_repeated_id_inside_one_batch(enabled):
    blue = enabled.agents["blue"]
    e = envelope(blue)
    results = (await post(enabled, [e, dict(e), {**e, "raw_message": "other"}])).json()["results"]
    assert [x["status"] for x in results] == ["accepted", "duplicate", "rejected"]
    assert results[0]["receipt_id"] == results[1]["receipt_id"] and results[2]["code"] == 409
    assert len(await inbox_rows(enabled)) == 1


async def test_group_budget_turns_the_rest_into_retries(enabled, monkeypatch):
    from app.core.config import settings
    blue = enabled.agents["blue"]
    monkeypatch.setattr(settings, "EVIDENCE_GROUP_BUDGET_BYTES", 1500)
    events = [envelope(blue) for _ in range(5)]
    results = (await post(enabled, events)).json()["results"]
    statuses = [x["status"] for x in results]
    assert statuses[0] == "accepted" and "retry" in statuses
    first_retry = statuses.index("retry")
    assert all(s == "retry" for s in statuses[first_retry:])  # no reordering past a full budget
    assert all(x["code"] == 429 for x in results[first_retry:])
    assert len(await inbox_rows(enabled)) == first_retry


async def test_request_level_refusals(enabled, monkeypatch):
    from app.core.config import settings
    blue, red = enabled.agents["blue"], enabled.agents["red"]
    assert (await post(enabled, [envelope(red)])).status_code == 403  # another agent's evidence
    assert (await post(enabled, [])).status_code == 422
    assert (await post(enabled, [envelope(blue)] * 501)).status_code == 422
    r = await enabled.client.post("/api/ingest/v2/logs", content=b"{" + b" " * (5 << 20) + b"}", headers=enabled.headers)
    assert r.status_code == 413
    assert (await enabled.client.post("/api/ingest/v2/logs", content=b"not json", headers=enabled.headers)).status_code == 422
    monkeypatch.setattr(settings, "EVIDENCE_INGEST_ENABLED", False)
    assert (await post(enabled, [envelope(blue)])).status_code == 503
    assert len(await inbox_rows(enabled)) == 0


async def test_unapproved_agent_is_refused(enabled):
    from app.models import models
    blue = enabled.agents["blue"]
    async with enabled.sessions() as db:
        agent = await db.get(models.Agent, blue)
        agent.approved = False
        await db.commit()
    r = await post(enabled, [envelope(blue)])
    assert r.status_code == 403 and r.json()["detail"] == "pending_approval"


async def test_heartbeat_advertises_the_batch_limit(enabled):
    blue = enabled.agents["blue"]
    body = (await enabled.client.post("/api/ingest/heartbeat", json={"agent_id": str(blue), "status": "online"},
                                      headers=enabled.headers)).json()
    assert body["evidence_protocols"] == [2] and body["evidence_batch_max"] == 500
