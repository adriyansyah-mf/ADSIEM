"""Agent tokens rotate over the heartbeat, only for agents that can store the
new one; the previous token keeps working through its grace (needs TEST_DATABASE_URL)."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from app.core.config import settings
from app.models.models import Agent

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


async def _heartbeat(env, token, capable=True):
    body = {"agent_id": str(env.agents["blue"]), "version": "test"}
    if capable:
        body["token_rotation"] = 1
    return await env.client.post("/api/ingest/heartbeat", json=body, headers={"X-Agent-Token": token})


async def _set(env, **values):
    async with env.sessions() as db:
        await db.execute(update(Agent).where(Agent.id == env.agents["blue"]).values(**values))
        await db.commit()


async def _row(env):
    async with env.sessions() as db:
        return await db.get(Agent, env.agents["blue"])


async def test_a_fresh_token_is_not_rotated(evidence_api):
    await _set(evidence_api, token_issued_at=datetime.now(timezone.utc))
    resp = await _heartbeat(evidence_api, "blue-token")
    assert resp.status_code == 200 and resp.json()["agent_token"] is None


async def test_a_due_token_rotates_and_the_old_one_works_through_its_grace(evidence_api):
    env = evidence_api
    await _set(env, token_issued_at=datetime.now(timezone.utc) - timedelta(days=settings.AGENT_TOKEN_ROTATE_DAYS + 1))
    new = (await _heartbeat(env, "blue-token")).json()["agent_token"]
    assert new and new != "blue-token"
    # the new token works, and so does the old one (requests in flight, a restart before it was stored)
    assert (await _heartbeat(env, new)).json()["agent_token"] is None
    assert (await env.client.post("/api/ingest/logs", headers=BLUE, json={"entries": [{
        "agent_id": str(env.agents["blue"]), "hostname": "h", "log_type": "x", "raw_message": "y",
        "received_at": datetime.now(timezone.utc).isoformat()}]})).status_code == 202
    row = await _row(env)
    assert row.prev_token_expires_at > datetime.now(timezone.utc) + timedelta(hours=settings.AGENT_TOKEN_GRACE_HOURS - 1)


async def test_an_agent_still_on_the_old_token_gets_a_new_one_again(evidence_api):
    env = evidence_api
    await _set(env, token_rotate_requested=True)
    first = (await _heartbeat(env, "blue-token")).json()["agent_token"]
    # the agent never stored `first` and heartbeats with the old token again
    again = (await _heartbeat(env, "blue-token")).json()["agent_token"]
    assert again and again != first
    assert (await _heartbeat(env, again)).status_code == 200
    assert (await _heartbeat(env, "blue-token")).status_code == 200      # still in grace


async def test_the_previous_token_stops_working_after_its_grace(evidence_api):
    env = evidence_api
    await _set(env, token_rotate_requested=True)
    new = (await _heartbeat(env, "blue-token")).json()["agent_token"]
    await _set(env, prev_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert (await _heartbeat(env, "blue-token")).status_code == 401
    assert (await _heartbeat(env, new)).status_code == 200


async def test_agents_that_cannot_store_a_token_are_never_rotated(evidence_api):
    env = evidence_api
    await _set(env, token_rotate_requested=True, token_issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    resp = await _heartbeat(env, "blue-token", capable=False)
    assert resp.status_code == 200 and resp.json()["agent_token"] is None
    assert (await _row(env)).token_rotate_requested is True              # waits for a capable heartbeat


async def test_another_agents_token_never_matches(evidence_api):
    env = evidence_api
    await _set(env, token_rotate_requested=True)
    await _heartbeat(env, "blue-token")
    # red's own token still authenticates red only
    resp = await env.client.post("/api/ingest/heartbeat", json={"agent_id": str(env.agents["red"]), "version": "t"},
                                 headers={"X-Agent-Token": "red-token"})
    assert resp.status_code == 200


async def test_a_stale_concurrent_heartbeat_cannot_rotate_again(evidence_api):
    # heartbeat A timed out on the agent's side while B ran: both loaded the
    # same token; only the first may rotate, or the agent could hold a token
    # that is neither current nor previous
    from app.api.routes import ingest
    from app.schemas.schemas import HeartbeatRequest

    env = evidence_api
    await _set(env, token_rotate_requested=True)
    body = HeartbeatRequest(agent_id=env.agents["blue"], status="online", version="t", token_rotation=1)
    async with env.sessions() as db:
        stale = await db.get(Agent, env.agents["blue"])
        now = datetime.now(timezone.utc)
        first = await ingest._rotate_token(db, None, stale, body, now)
        second = await ingest._rotate_token(db, None, stale, body, now)
    assert first and second is None
    assert (await _heartbeat(env, first)).status_code == 200
