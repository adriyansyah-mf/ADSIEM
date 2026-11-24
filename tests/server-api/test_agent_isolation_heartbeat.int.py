# tests/server-api/test_agent_isolation_heartbeat.int.py
"""Heartbeat isolated: the agent's own isolation state (ransomguard isolates
without a task) updates Agent.is_isolated, so the agent page offers "Lift
isolation"; it is ignored while an isolate/unisolate task is on its way, and
heartbeats without it (older agents) change nothing."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.models.models import Agent, AgentTask

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


async def heartbeat(env, **fields):
    resp = await env.client.post("/api/ingest/heartbeat", json={
        "agent_id": str(env.agents["blue"]), "version": "1.34.4", **fields}, headers=BLUE)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def is_isolated(env):
    async with env.sessions() as db:
        return (await db.get(Agent, env.agents["blue"])).is_isolated


async def add_task(env, task_type, status, age=timedelta(0)):
    async with env.sessions() as db:
        db.add(AgentTask(agent_id=env.agents["blue"], task_type=task_type, status=status,
                         created_at=datetime.now(timezone.utc) - age))
        await db.commit()


async def test_self_isolation_and_release_are_recorded(evidence_api):
    assert not await is_isolated(evidence_api)
    await heartbeat(evidence_api, isolated=True)  # ransomguard isolated the host
    assert await is_isolated(evidence_api)
    await heartbeat(evidence_api, isolated=False)  # released (offline release, local unisolate)
    assert not await is_isolated(evidence_api)


async def test_older_agents_leave_the_state_alone(evidence_api):
    await heartbeat(evidence_api, isolated=True)
    await heartbeat(evidence_api)
    assert await is_isolated(evidence_api)


@pytest.mark.parametrize("status", ["pending", "dispatched", "running"])
async def test_an_open_isolation_task_holds_the_state(evidence_api, status):
    # the analyst clicked Isolate: is_isolated is already True, the heartbeat
    # still carries the state from before the task ran
    async with evidence_api.sessions() as db:
        (await db.get(Agent, evidence_api.agents["blue"])).is_isolated = True
        await db.commit()
    await add_task(evidence_api, "isolate_host", status)
    await heartbeat(evidence_api, isolated=False)
    assert await is_isolated(evidence_api)


async def test_a_finished_or_stale_task_does_not_hold_it(evidence_api):
    await add_task(evidence_api, "unisolate_host", "done")
    await add_task(evidence_api, "isolate_host", "dispatched", age=timedelta(hours=2))
    await add_task(evidence_api, "process_list", "pending")
    await heartbeat(evidence_api, isolated=True)
    assert await is_isolated(evidence_api)
