# tests/server-api/test_ingest_log_batch.int.py
"""POST /api/ingest/logs: many legacy log lines per request, queued in
order with the agent's identity from its token; heartbeats advertise it."""
import asyncio

import pytest


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


def entry(i, log_type="windows_etw_image"):
    return {"agent_id": "00000000-0000-0000-0000-000000000000", "log_type": log_type, "raw_message": f"line {i}",
            "received_at": "2026-11-02T10:00:00Z", "hostname": "spoofed", "location": ""}


async def test_batch_is_queued_with_the_tokens_agent(evidence_api):
    c, redis = evidence_api.client, evidence_api.redis
    headers = {"X-Agent-Token": "blue-token"}
    r = await c.post("/api/ingest/logs", json={"entries": [entry(1), entry(2, "known_malware")]}, headers=headers)
    assert r.status_code == 202 and r.json() == {"status": "queued", "accepted": 2}
    queued = [a[1] for a in redis.items]
    assert [q["raw_message"] for q in queued] == ["line 1", "line 2"]
    assert all(q["agent_id"] == str(evidence_api.agents["blue"]) and q["hostname"] == "blue-host" for q in queued)
    assert queued[1]["log_type"] == "known_malware"

    assert (await c.post("/api/ingest/logs", json={"entries": [entry(1)]},
                         headers={"X-Agent-Token": "nope"})).status_code == 401
    assert (await c.post("/api/ingest/logs", json={"entries": []}, headers=headers)).status_code == 422
    too_many = {"entries": [entry(i) for i in range(501)]}
    assert (await c.post("/api/ingest/logs", json=too_many, headers=headers)).status_code == 422


async def test_heartbeat_advertises_batch_size(evidence_api):
    r = await evidence_api.client.post("/api/ingest/heartbeat", json={"agent_id": str(evidence_api.agents["blue"]),
                                                                       "hostname": "blue-host"},
                                       headers={"X-Agent-Token": "blue-token"})
    assert r.status_code == 200, r.text
    assert r.json()["log_batch_max"] == 500
