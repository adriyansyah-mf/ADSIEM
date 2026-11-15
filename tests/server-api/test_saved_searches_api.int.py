"""Saved searches and custom dashboards (routes/saved_searches.py,
routes/dashboards.py, services/saved_searches.py): who sees and edits what,
running always scoped to the caller's group, the four widget shapes, and a
shared dashboard needing shared searches."""
import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import dashboards, saved_searches
from app.core import es_client
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Role, User

READ = ("logs:read",)


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    calls = []

    async def aggregate(query, aggs, size=0):
        calls.append(("aggregate", query, aggs))
        out = {}
        if "t" in aggs:
            out = {"t": {"buckets": [{"key_as_string": "2026-11-15T10:00:00Z", "key": 1, "doc_count": 4}]}}
        if "top" in aggs:
            out = {"top": {"buckets": [{"key": "linux_auth", "doc_count": 9}]}}
        return {"total": 42, "aggregations": out}

    async def search(query, size=25, sort=None, search_after=None):
        calls.append(("search", query, size))
        return [{"id": "e1", "created_at": "2026-11-15T10:00:00Z", "log_type": "linux_auth", "hostname": "web-01",
                 "raw_message": "Failed password for root from 45.129.56.138"}], 1, None

    monkeypatch.setattr(es_client, "aggregate", aggregate)
    monkeypatch.setattr(es_client, "search", search)

    async def person(name, group="blue", role="analyst", perms=READ):
        async with evidence_api.sessions() as db:
            r = Role(name=f"{role}-{uuid4().hex[:6]}")
            db.add(r)
            await db.flush()
            u = User(username=f"{name}-{uuid4().hex[:6]}", email=f"{uuid4().hex[:8]}@x.test", password_hash="x",
                     role_id=r.id, group_id=group)
            db.add(u)
            await db.commit()
            return SimpleNamespace(id=u.id, group_id=group, username=name, role=SimpleNamespace(
                name=role, permissions=[SimpleNamespace(name=p) for p in perms]))

    evidence_api.person = person
    evidence_api.calls = calls
    evidence_api.user = await person("ana")
    app = FastAPI()
    app.include_router(saved_searches.router)
    app.include_router(dashboards.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _save(env, **kw):
    body = {"name": "SSH failures", "kind": "logs", "query": "Failed password", "log_type": "linux_auth", **kw}
    r = await env.api.post("/api/saved-searches", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def test_who_sees_and_edits_a_search(env):
    ana = env.user
    private = await _save(env, name="mine only")
    shared = await _save(env, name="team", shared=True)
    assert private["mine"] and private["editable"] and private["group_id"] == "blue"

    env.user = await env.person("budi")  # same group
    seen = {s["name"]: s for s in (await env.api.get("/api/saved-searches")).json()}
    assert set(seen) == {"team"} and not seen["team"]["mine"] and not seen["team"]["editable"]
    assert (await env.api.get(f"/api/saved-searches/{private['id']}/run")).status_code == 404
    assert (await env.api.put(f"/api/saved-searches/{shared['id']}", json={"name": "x"})).status_code == 403
    assert (await env.api.delete(f"/api/saved-searches/{shared['id']}")).status_code == 403

    env.user = await env.person("admin", role="admin")  # the group's admin may tidy shared ones
    assert (await env.api.put(f"/api/saved-searches/{shared['id']}",
                              json={"name": "team (renamed)", "query": "Failed", "shared": True})).status_code == 200

    env.user = await env.person("rudi", group="red")
    assert (await env.api.get("/api/saved-searches")).json() == []
    assert (await env.api.get(f"/api/saved-searches/{shared['id']}/run")).status_code == 404

    env.user = await env.person("root", group="", role="superadmin")
    assert {s["name"] for s in (await env.api.get("/api/saved-searches")).json()} == {"mine only", "team (renamed)"}

    env.user = ana
    assert (await env.api.delete(f"/api/saved-searches/{private['id']}")).status_code == 204


async def test_running_uses_the_callers_group_and_window(env):
    shared = await _save(env, shared=True, filter_tree={"logic": "AND", "children": [
        {"field": "source_ip", "operator": "equals", "value": "45.129.56.138"}]})
    env.user = await env.person("budi")
    r = await env.api.get(f"/api/saved-searches/{shared['id']}/run", params={"viz": "count", "hours": 6})
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 42 and r.json()["search"]["name"] == "SSH failures"
    _, query, _ = env.calls[-1]
    filters = query["bool"]["filter"]
    assert {"term": {"group_id": "blue"}} in filters and {"term": {"log_type": "linux_auth"}} in filters
    assert any("range" in f for f in filters)
    assert any(f.get("query_string", {}).get("query") == "Failed password" for f in filters)
    assert any("bool" in f for f in filters)  # the builder's tree

    timeline = (await env.api.get(f"/api/saved-searches/{shared['id']}/run", params={"viz": "timeline", "hours": 48})).json()
    assert timeline["interval"] == "1h" and timeline["points"] == [{"t": "2026-11-15T10:00:00Z", "count": 4}]
    top = (await env.api.get(f"/api/saved-searches/{shared['id']}/run", params={"viz": "top", "field": "log_type"})).json()
    assert top["values"] == [{"value": "linux_auth", "count": 9}]
    table = (await env.api.get(f"/api/saved-searches/{shared['id']}/run", params={"viz": "table"})).json()
    assert table["rows"][0]["hostname"] == "web-01" and "Failed password" in table["rows"][0]["message"]
    bad = await env.api.get(f"/api/saved-searches/{shared['id']}/run", params={"viz": "top", "field": "raw_message"})
    assert bad.status_code == 422


async def test_a_malformed_tree_is_refused(env):
    r = await env.api.post("/api/saved-searches", json={"name": "x", "filter_tree": {"logic": "AND", "children": [
        {"field": "password_hash", "operator": "equals", "value": "a"}]}})
    assert r.status_code in (400, 422), r.text


async def test_a_shared_dashboard_needs_shared_searches(env):
    private = await _save(env, name="mine only")
    widget = {"title": "SSH failures today", "search_id": private["id"], "viz": "timeline", "hours": 24, "width": 2}
    r = await env.api.post("/api/dashboards", json={"name": "SOC wall", "shared": True, "widgets": [widget]})
    assert r.status_code == 422 and "mine only" in r.text
    r = await env.api.post("/api/dashboards", json={"name": "SOC wall", "widgets": [widget]})
    assert r.status_code == 201, r.text
    dash = r.json()
    assert dash["widgets"][0]["viz"] == "timeline" and dash["widgets"][0]["id"]

    await env.api.put(f"/api/saved-searches/{private['id']}", json={
        "name": "mine only", "query": "Failed password", "log_type": "linux_auth", "shared": True})
    r = await env.api.put(f"/api/dashboards/{dash['id']}", json={"name": "SOC wall", "shared": True, "widgets": [widget]})
    assert r.status_code == 200, r.text

    env.user = await env.person("budi")
    assert [d["name"] for d in (await env.api.get("/api/dashboards")).json()] == ["SOC wall"]
    assert (await env.api.get(f"/api/dashboards/{dash['id']}")).json()["editable"] is False
    env.user = await env.person("rudi", group="red")
    assert (await env.api.get(f"/api/dashboards/{dash['id']}")).status_code == 404
    # a red user cannot build on blue's search either
    r = await env.api.post("/api/dashboards", json={"name": "x", "widgets": [widget]})
    assert r.status_code == 422


async def test_widget_validation(env):
    s = await _save(env)
    bad_field = {"search_id": s["id"], "viz": "top", "field": "password"}
    assert (await env.api.post("/api/dashboards", json={"name": "x", "widgets": [bad_field]})).status_code == 422
    too_many = [{"search_id": s["id"]} for _ in range(25)]
    assert (await env.api.post("/api/dashboards", json={"name": "x", "widgets": too_many})).status_code == 422
