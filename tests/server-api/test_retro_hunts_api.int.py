"""Retro-hunt API and queueing (routes/retro_hunts.py, services/retro_hunts.py):
analysts start IOC and rule hunts in their own group; adding an indicator to
a blocklist queues one automatically, once per hour, unless turned off."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import retro_hunts as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import PlatformSetting, RetroHunt, Rule
from app.services import retro_hunts as svc


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    evidence_api.user = evidence_api.make_user(perms=("alerts:read", "alerts:manage"))
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _hunts(env):
    async with env.sessions() as db:
        return (await db.execute(select(RetroHunt).order_by(RetroHunt.created_at))).scalars().all()


async def test_an_analyst_starts_an_ioc_hunt_in_their_group(env):
    r = await env.api.post("/api/retro-hunts", json={"kind": "ioc", "ioc_type": "ip", "ioc_value": " 45.129.56.138 ",
                                                     "days": 14, "group_id": "red"})
    assert r.status_code == 201, r.text
    out = r.json()
    assert (out["ioc_value"], out["group_id"], out["days"], out["status"], out["trigger"]) == \
        ("45.129.56.138", "blue", 14, "pending", "manual")  # scoped users cannot hunt another group
    assert out["create_alerts"] is True
    assert (await env.api.get(f"/api/retro-hunts/{out['id']}")).json()["id"] == out["id"]
    assert [h["id"] for h in (await env.api.get("/api/retro-hunts")).json()] == [out["id"]]


@pytest.mark.parametrize("body", [
    {"kind": "ioc", "ioc_type": "ip", "ioc_value": "not-an-ip"},
    {"kind": "ioc", "ioc_type": "hash", "ioc_value": "1234"},
    {"kind": "ioc", "ioc_value": "evil.example"},
    {"kind": "ioc", "ioc_type": "domain", "ioc_value": "evil.example", "days": 0},
])
async def test_bad_hunts_are_refused(env, body):
    assert (await env.api.post("/api/retro-hunts", json=body)).status_code == 422


async def test_a_rule_hunt_reports_by_default_and_needs_a_visible_rule(env):
    async with env.sessions() as db:
        mine = Rule(title="Webshell Test", content="title: x", level="high", tags=[], mitre_tags=[], group_id="blue")
        theirs = Rule(title="Red only", content="title: y", level="low", tags=[], mitre_tags=[], group_id="red")
        db.add_all([mine, theirs])
        await db.commit()
    r = await env.api.post("/api/retro-hunts", json={"kind": "rule", "rule_id": str(mine.id), "days": 7})
    assert r.status_code == 201 and r.json()["rule_title"] == "Webshell Test" and r.json()["create_alerts"] is False
    assert (await env.api.post("/api/retro-hunts", json={"kind": "rule", "rule_id": str(theirs.id)})).status_code == 404


async def test_starting_needs_alerts_manage(env):
    env.user = env.make_user(perms=("alerts:read",))
    r = await env.api.post("/api/retro-hunts", json={"kind": "ioc", "ioc_type": "domain", "ioc_value": "evil.example"})
    assert r.status_code == 403
    assert (await env.api.get("/api/retro-hunts")).status_code == 200


async def test_a_blocked_indicator_is_queued_once_an_hour(env):
    async with env.sessions() as db:
        first = await svc.enqueue_ioc(db, "domain", "Evil.Example", "blue", "web_block")
        again = await svc.enqueue_ioc(db, "domain", "evil.example", "blue", "web_block")
        other_group = await svc.enqueue_ioc(db, "domain", "evil.example", "red", "web_block")
        junk = await svc.enqueue_ioc(db, "ip", "10.0.0.0/8", "blue", "ip_block")
    assert first is not None and first.ioc_value == "evil.example" and first.days == 30
    assert again is None and other_group is not None and junk is None
    assert [h.group_id for h in await _hunts(env)] == ["blue", "red"]


async def test_automatic_hunts_can_be_turned_off_but_manual_ones_still_run(env):
    async with env.sessions() as db:
        db.add(PlatformSetting(key="retro_hunt_on_block", value="false"))
        db.add(PlatformSetting(key="retro_hunt_days", value="90"))
        await db.commit()
        assert await svc.enqueue_ioc(db, "hash", "d41d8cd98f00b204e9800998ecf8427e", "*", "malware_hash") is None
        manual = await svc.enqueue_ioc(db, "hash", "d41d8cd98f00b204e9800998ecf8427e", "*", "manual")
    assert manual is not None and manual.days == 90


def test_only_a_single_address_block_is_hunted():
    assert svc.single_ip("45.129.56.138/32") == "45.129.56.138"
    assert svc.single_ip("2001:db8::1/128") == "2001:db8::1"
    assert svc.single_ip("45.129.56.0/24") is None and svc.single_ip("junk") is None
