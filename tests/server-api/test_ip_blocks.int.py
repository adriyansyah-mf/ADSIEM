# tests/server-api/test_ip_blocks.int.py
"""IP IoC blocklist: the agent delta sync (group scoping, the "*" list,
removal and expiry propagation, the policy's off/detect/block mode) and the
dashboard routes' validation and group scoping."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import ip_blocks as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Agent, AgentPolicy, IPBlockEntry
from app.services import agent_policy
from app.services import ip_blocks as ib

BLUE = {"X-Agent-Token": "blue-token"}
EVIL = "45.33.32.156"


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None):
        evidence_api.audits.append((actor_id, action, resource_id, detail))

    monkeypatch.setattr(routes, "audit_log", audit)
    app = FastAPI()
    app.include_router(routes.agent_router)
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    ib.invalidate()
    agent_policy.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api
    ib.invalidate()
    agent_policy.invalidate()


async def add(env, cidr, group="blue", source="manual", status="active", expires=None, reason="r"):
    async with env.sessions() as db:
        row = IPBlockEntry(cidr=cidr, group_id=group, source=source, status=status, expires_at=expires, reason=reason)
        db.add(row)
        await db.commit()
        return row.id


async def set_mode(env, group, mode):
    async with env.sessions() as db:
        row = await db.get(AgentPolicy, group) or AgentPolicy(group_id=group, settings={})
        row.settings = {**(row.settings or {}), "ip_ioc": mode}
        db.add(row)
        await db.commit()
    agent_policy.invalidate()
    ib.invalidate()


async def sync(env, since=0, headers=BLUE):
    r = await env.api.post("/api/ingest/ip-blocklist", json={"since": since}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def apply(state, out):
    if out["reset"]:
        state = set()
    for c in out["changes"]:
        (state.add if c["action"] == "block" else state.discard)(c["cidr"])
    return state


async def test_delta_sync_scopes_groups_and_propagates_removals(env):
    evil = await add(env, f"{EVIL}/32")
    await add(env, "8.8.4.4/32", group="red")
    await add(env, "1.0.0.0/24", group="*", source="feed")
    out = await sync(env)
    state = apply(set(), out)
    assert state == {f"{EVIL}/32", "1.0.0.0/24"}
    assert out["reset"] is True and out["mode"] == "block" and out["version"] == f"blue:{out['seq']}:block"
    async with env.sessions() as db:
        agent = await db.get(Agent, env.agents["blue"])
        assert await ib.agent_version(db, agent) == out["version"]
        row = await db.get(IPBlockEntry, evil)
        await ib.remove(db, row)
    await add(env, "9.9.9.9/32")
    out2 = await sync(env, out["seq"])
    assert out2["reset"] is False
    assert apply(state, out2) == {"9.9.9.9/32", "1.0.0.0/24"}


async def test_off_sends_nothing_and_detect_is_reported(env):
    await add(env, f"{EVIL}/32")
    await set_mode(env, "blue", "off")
    out = await sync(env)
    assert out["mode"] == "off" and out["changes"] == [] and out["version"] == ""
    async with env.sessions() as db:
        assert await ib.agent_version(db, await db.get(Agent, env.agents["blue"])) == ""
    await set_mode(env, "blue", "detect")
    out = await sync(env)
    assert out["mode"] == "detect" and apply(set(), out) == {f"{EVIL}/32"} and out["version"].endswith(":detect")


async def test_expired_entries_are_removed(env):
    entry = await add(env, f"{EVIL}/32", expires=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert apply(set(), await sync(env)) == set()
    async with env.sessions() as db:
        assert (await db.get(IPBlockEntry, entry)).status == "removed"


async def test_an_address_stays_blocked_while_any_entry_is_active(env):
    manual = await add(env, f"{EVIL}/32", source="manual", reason="analyst")
    await add(env, f"{EVIL}/32", source="soar", reason="playbook")
    out = await sync(env)
    assert out["changes"] == [{"cidr": f"{EVIL}/32", "action": "block", "source": "manual", "reason": "analyst"}]
    async with env.sessions() as db:
        await ib.remove(db, await db.get(IPBlockEntry, manual))
    out2 = await sync(env, out["seq"])
    assert out2["changes"] == [{"cidr": f"{EVIL}/32", "action": "block", "source": "soar", "reason": "playbook"}]


async def test_pages_continue_until_caught_up(env, monkeypatch):
    for i in range(5):
        await add(env, f"45.33.32.{10 + i}/32")
    monkeypatch.setattr(ib, "SYNC_PAGE", 2)
    original = ib.delta

    async def small(db, group_id, since, continuing=False, limit=2):
        return await original(db, group_id, since, continuing, limit=2)
    monkeypatch.setattr(ib, "delta", small)
    state, since, continuing, pages = set(), 0, False, 0
    while True:
        r = await env.api.post("/api/ingest/ip-blocklist", json={"since": since, "continuing": continuing},
                               headers=BLUE)
        out = r.json()
        state = apply(state, out) if not continuing else state | {c["cidr"] for c in out["changes"]}
        pages += 1
        if not out["more"]:
            break
        assert out["version"] == ""
        since, continuing = out["seq"], True
    assert pages == 3 and len(state) == 5 and out["version"].startswith("blue:")


async def test_dashboard_validates_and_scopes(env):
    env.user = env.make_user(role="admin", group="blue", perms=("agents:manage", "alerts:read"))
    r = await env.api.post("/api/ip-blocks", json={"value": "127.0.0.1"})
    assert r.status_code == 422 and "loopback" in r.json()["detail"]
    r = await env.api.post("/api/ip-blocks", json={"value": "10.0.0.0/8"})
    assert r.status_code == 422 and "too broad" in r.json()["detail"]
    r = await env.api.post("/api/ip-blocks", json={"value": "10.1.2.3", "reason": "internal pivot"})
    assert r.status_code == 201 and r.json()["cidr"] == "10.1.2.3/32"  # an analyst may block an internal host
    r = await env.api.post("/api/ip-blocks", json={"value": EVIL, "group_id": "red"})
    assert r.status_code == 404  # not their group
    r = await env.api.post("/api/ip-blocks", json={"value": EVIL})
    assert r.status_code == 201 and r.json()["group_id"] == "blue"
    entry = r.json()["id"]
    red = await add(env, "8.8.4.4/32", group="red")
    listed = (await env.api.get("/api/ip-blocks")).json()
    assert {i["cidr"] for i in listed["items"]} == {"10.1.2.3/32", f"{EVIL}/32"} and listed["mode"] == "block"
    assert (await env.api.delete(f"/api/ip-blocks/{red}")).status_code == 404
    assert (await env.api.delete(f"/api/ip-blocks/{entry}")).json() == {"status": "removed"}
    assert [a[1] for a in env.audits] == ["ip_block.add", "ip_block.add", "ip_block.remove"]
    r = await env.api.post("/api/ip-blocks/bulk", json={"action": "block", "values": ["9.9.9.9", "0.0.0.0"]})
    assert r.json()["done"] == 1 and r.json()["errors"][0]["value"] == "0.0.0.0"
