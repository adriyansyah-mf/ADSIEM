# tests/server-api/test_sensor_health_heartbeat.int.py
"""Heartbeat sensor_health: stored on the agent, and a sensor stopped between
two heartbeats becomes an agent_sensor_stopped health event; a bad
sensor_health is dropped without failing the heartbeat."""
import asyncio

import pytest

from app.models.models import Agent

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


async def heartbeat(env, sensors):
    resp = await env.client.post("/api/ingest/heartbeat", json={
        "agent_id": str(env.agents["blue"]), "version": "1.26.0", "sensor_health": sensors}, headers=BLUE)
    assert resp.status_code == 200, resp.text
    return resp.json()


def health_lines(env):
    return [data["raw_message"] for _, data in env.redis.items if data.get("log_type") == "siem_agent"]


async def test_sensor_health_is_stored_and_a_stop_is_reported(evidence_api):
    await heartbeat(evidence_api, {"etw": {"running": True, "events": 4000, "lost": 0,
                                           "last_event_at": "2026-11-13T08:00:00Z"}})
    async with evidence_api.sessions() as db:
        agent = await db.get(Agent, evidence_api.agents["blue"])
        assert agent.sensor_health["etw"]["events"] == 4000 and agent.sensor_health_at is not None
    assert not [l for l in health_lines(evidence_api) if "agent_sensor" in l]

    await heartbeat(evidence_api, {"etw": {"running": False, "events": 4100, "lost": 0,
                                           "error": "ETW session stopped"}})
    stopped = [l for l in health_lines(evidence_api) if l.startswith("event=agent_sensor_stopped")]
    assert stopped == ['event=agent_sensor_stopped version=1.26.0 sensor=etw error="ETW session stopped"']


async def test_an_invalid_sensor_health_does_not_fail_the_heartbeat(evidence_api):
    too_many = {f"s{i}": {"running": True, "events": 1} for i in range(40)}
    await heartbeat(evidence_api, too_many)
    await heartbeat(evidence_api, {"etw": {"running": True, "events": -5}})
    async with evidence_api.sessions() as db:
        assert (await db.get(Agent, evidence_api.agents["blue"])).sensor_health is None
