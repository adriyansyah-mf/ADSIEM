# tests/server-api/test_evidence_health.int.py
"""Durable agents report evidence health in the heartbeat: it is validated
and bounded on its own (a bad object never fails the heartbeat), stored with
the server's receipt time, kept when a legacy heartbeat omits it, and shown
as healthy/backlogged/blocked/degraded/not_reported with staleness."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

HEALTH = {"version": 1, "mode": "durable", "state": "degraded", "reason": "capacity",
          "queued_events": 3, "queued_bytes": 1024, "known_loss": {"capacity": 2}, "unknown_gaps": 1,
          "sources": {"file:/var/log/auth.log": {"state": "paused", "reason": "capacity",
                                                 "updated_at": "2026-10-24T10:00:00Z"}},
          "sender": {"state": "retrying", "reason": "status_503", "failures": 2}}


def heartbeat(agent_id, health=None, **extra):
    body = {"agent_id": str(agent_id), "status": "online", "version": "1.9.0", **extra}
    if health is not None:
        body["evidence_health"] = health
    return body


def test_health_uses_persisted_cumulative_counts():
    from app.schemas.schemas import HeartbeatRequest
    body = HeartbeatRequest(agent_id=uuid4(), evidence_health={
        "version": 1, "state": "degraded", "reason": "capacity", "queued_events": 3, "queued_bytes": 1024,
        "known_loss": {"capacity": 2}, "unknown_gaps": 0})
    assert body.evidence_health.known_loss["capacity"] == 2


def test_invalid_or_unbounded_health_is_dropped_not_the_heartbeat():
    from app.schemas.schemas import HeartbeatRequest
    bad = [
        {**HEALTH, "state": "on fire"},
        {**HEALTH, "queued_events": -1},
        {**HEALTH, "queued_bytes": 1 << 64},
        {**HEALTH, "known_loss": {"made_up_reason": 1}},
        {**HEALTH, "sources": {f"file:/{i}": {"state": "healthy"} for i in range(257)}},
        {**HEALTH, "sources": {"file:/" + "x" * 600: {"state": "healthy"}}},
        {**HEALTH, "sources": {"file:/a": {"state": "healthy", "reason": "r" * 300}}},
        {**HEALTH, "version": 2},
        "not an object",
    ]
    for health in bad:
        body = HeartbeatRequest(agent_id=uuid4(), evidence_health=health)
        assert body.evidence_health is None, health
    # Go encodes nil maps as null and times with nanoseconds
    body = HeartbeatRequest(agent_id=uuid4(), evidence_health={
        "version": 1, "state": "healthy", "known_loss": None, "pending_loss": None, "sources": None,
        "last_receipt_at": "2026-10-24T01:02:03.123456789Z"})
    assert body.evidence_health.known_loss == {} and body.evidence_health.last_receipt_at.microsecond == 123456
    # newer agents may add fields: ignored, not rejected
    body = HeartbeatRequest(agent_id=uuid4(), evidence_health={**HEALTH, "future_field": 1})
    assert body.evidence_health.state == "degraded"


def test_status_needs_a_report_and_reads_the_sender():
    from app.services.evidence_status import evidence_status
    now = datetime.now(timezone.utc)
    assert evidence_status(None, None, now)["status"] == "not_reported"
    ok = {"version": 1, "state": "healthy", "queued_events": 0}
    assert evidence_status(ok, now, now) == {"status": "healthy", "reason": None, "reported_at": now.isoformat(), "stale": False}
    blocked = {**ok, "queued_events": 4, "sender": {"state": "blocked", "reason": "auth_blocked"}}
    assert evidence_status(blocked, now, now)["status"] == "blocked"
    assert evidence_status(blocked, now, now)["reason"] == "auth_blocked"
    old = (now - timedelta(minutes=10)).isoformat()
    assert evidence_status({**ok, "queued_events": 4, "oldest_queued_at": old}, now, now)["status"] == "backlogged"
    retrying = {**ok, "queued_events": 1, "sender": {"state": "retrying", "reason": "network"}}
    assert evidence_status(retrying, now, now)["status"] == "backlogged"
    fresh_queue = {**ok, "queued_events": 2, "oldest_queued_at": now.isoformat(), "sender": {"state": "sending"}}
    assert evidence_status(fresh_queue, now, now)["status"] == "healthy"
    degraded = {**ok, "state": "degraded", "reason": "storage_failure", "sender": {"state": "blocked"}}
    assert evidence_status(degraded, now, now)["status"] == "degraded"
    stale = evidence_status(ok, now - timedelta(minutes=5), now)
    assert stale["stale"] is True and stale["status"] == "healthy"  # last known state, marked stale


def test_agent_list_carries_the_summary_not_the_snapshot():
    from types import SimpleNamespace
    from app.schemas.schemas import AgentOut
    now = datetime.now(timezone.utc)
    row = dict(id=uuid4(), name="web01", hostname="web01", group_id="blue", version="1.9.0", status="online",
               approved=True, is_isolated=False, last_seen_at=now, flow_poll_at=None, enrolled_at=now, log_sources=[])
    legacy = AgentOut.model_validate(SimpleNamespace(**row, evidence_health=None, evidence_health_at=None))
    assert legacy.model_dump()["evidence"]["status"] == "not_reported"
    durable = AgentOut.model_validate(SimpleNamespace(**row, evidence_health=HEALTH, evidence_health_at=now)).model_dump()
    assert durable["evidence"]["status"] == "degraded" and durable["evidence"]["reason"] == "capacity"
    assert "evidence_health" not in durable and "evidence_health_at" not in durable


async def test_heartbeat_stores_health_with_server_receipt_time(evidence_api):
    blue = evidence_api.agents["blue"]
    before = datetime.now(timezone.utc)
    r = await evidence_api.client.post("/api/ingest/heartbeat", json=heartbeat(blue, HEALTH, group_id="red"),
                                       headers={"X-Agent-Token": "blue-token"})
    assert r.status_code == 200, r.text
    detail = (await evidence_api.client.get(f"/api/agents/{blue}/evidence")).json()
    assert detail["status"] == "degraded" and detail["reason"] == "capacity" and detail["stale"] is False
    assert detail["health"]["known_loss"] == {"capacity": 2}
    assert detail["health"]["sources"]["file:/var/log/auth.log"]["state"] == "paused"
    assert datetime.fromisoformat(detail["reported_at"]) >= before
    assert detail["inbox"] == {"pending": 0, "completed": 0, "dead_letter": 0, "oldest_pending_at": None,
                               "dead_letters": []}


async def test_legacy_and_invalid_reports_keep_the_last_snapshot(evidence_api):
    blue = evidence_api.agents["blue"]
    headers = {"X-Agent-Token": "blue-token"}
    await evidence_api.client.post("/api/ingest/heartbeat", json=heartbeat(blue), headers=headers)
    assert (await evidence_api.client.get(f"/api/agents/{blue}/evidence")).json()["status"] == "not_reported"

    await evidence_api.client.post("/api/ingest/heartbeat", json=heartbeat(blue, HEALTH), headers=headers)
    r = await evidence_api.client.post("/api/ingest/heartbeat", json=heartbeat(blue, {**HEALTH, "state": "x"}),
                                       headers=headers)
    assert r.status_code == 200  # the bad health object did not fail the heartbeat
    await evidence_api.client.post("/api/ingest/heartbeat", json=heartbeat(blue), headers=headers)
    detail = (await evidence_api.client.get(f"/api/agents/{blue}/evidence")).json()
    assert detail["status"] == "degraded" and detail["health"]["known_loss"] == {"capacity": 2}


async def test_stale_report_keeps_its_status(evidence_api):
    from app.models import models
    blue = evidence_api.agents["blue"]
    async with evidence_api.sessions() as db:
        agent = await db.get(models.Agent, blue)
        agent.evidence_health = {**HEALTH, "state": "healthy", "reason": "", "sender": {"state": "sending"}}
        agent.evidence_health_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        await db.commit()
    detail = (await evidence_api.client.get(f"/api/agents/{blue}/evidence")).json()
    # last known state, flagged stale (queue is young and the sender was sending)
    assert detail["stale"] is True and detail["status"] == "healthy"


async def test_other_groups_agent_is_not_found(evidence_api):
    red = evidence_api.agents["red"]
    r = await evidence_api.client.get(f"/api/agents/{red}/evidence")
    assert r.status_code == 404
    evidence_api.user = evidence_api.make_user(role="superadmin", group="default", perms=())
    assert (await evidence_api.client.get(f"/api/agents/{red}/evidence")).status_code == 200
