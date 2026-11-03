# tests/server-api/test_yara_builtin.int.py
"""The built-in YARA pack: synced into yara_rules enabled, idempotent, an
upgrade updates the content but keeps an analyst's disable, the old inline
seed is cleaned up only when untouched, and built-ins cannot be edited or
deleted in place."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import yara_rules
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import YaraRule
from app.services import yara_builtin


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(yara_rules.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


def admin(env):
    return env.make_user(role="admin", perms=("rules:create", "rules:update", "rules:delete", "rules:read"))


async def _rows(env):
    async with env.sessions() as db:
        return {r.name: r for r in (await db.execute(select(YaraRule))).scalars().all()}


async def test_pack_syncs_and_keeps_toggles(api):
    pack = yara_builtin.load_pack()
    names = [p["name"] for p in pack]
    assert sum(n.startswith("builtin/") for n in names) >= 7
    # the community pack (yara/community, YARA-Forge sets with allowed licences) loads next to it
    community = [p for p in pack if p["name"].startswith("community/")]
    assert community and all(p["description"].startswith("Community: ") for p in community)
    assert all(n.startswith(("builtin/", "community/")) for n in names)

    legacy = yara_rules.legacy_contents()
    async with api.sessions() as db:  # the old inline seed: one untouched, one edited
        db.add(YaraRule(name="eicar_test", content=legacy["eicar_test"], origin="manual"))
        db.add(YaraRule(name="webshell_php", content="rule mine { condition: false }", origin="manual"))
        await db.commit()

    out = await yara_builtin.sync_builtin_rules(legacy, sessions=api.sessions)
    assert out["added"] == len(pack) and out["removed"] == 1
    rows = await _rows(api)
    assert "eicar_test" not in rows and "webshell_php" in rows
    built = {n: r for n, r in rows.items() if r.origin == "builtin"}
    assert len(built) == len(pack) and all(r.is_enabled for r in built.values())

    again = await yara_builtin.sync_builtin_rules(legacy, sessions=api.sessions)
    assert again == {"added": 0, "updated": 0, "removed": 0, "rules": len(pack)}

    # an analyst disabled one; an upgrade changes its content: updated, still disabled
    name = pack[0]["name"]
    async with api.sessions() as db:
        r = (await db.execute(select(YaraRule).where(YaraRule.name == name))).scalar_one()
        r.is_enabled, r.content = False, "rule old { condition: false }"
        await db.commit()
    assert (await yara_builtin.sync_builtin_rules(legacy, sessions=api.sessions))["updated"] == 1
    r = (await _rows(api))[name]
    assert r.content == pack[0]["content"] and r.is_enabled is False


async def test_builtins_cannot_be_edited_or_deleted(api):
    await yara_builtin.sync_builtin_rules({}, sessions=api.sessions)
    api.user = admin(api)
    c = api.api
    rows = await _rows(api)
    b = next(r for n, r in rows.items() if n.startswith("builtin/"))
    body = {"name": b.name, "description": b.description or "", "content": "rule x { condition: true }"}
    assert (await c.put(f"/api/yara-rules/{b.id}", json=body)).status_code == 409
    assert (await c.delete(f"/api/yara-rules/{b.id}")).status_code == 409
    assert (await c.patch(f"/api/yara-rules/{b.id}/toggle")).status_code == 200  # disabling is fine
    builtins = (await c.get("/api/yara-rules/builtins")).json()
    assert any(p["name"] == b.name for p in builtins)
