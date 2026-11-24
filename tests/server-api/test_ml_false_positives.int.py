# tests/server-api/test_ml_false_positives.int.py
"""Fleet-wide ML false positives: who may change them, and every agent gets
them as sha256 exclusions with the ml scope (a new policy version) while the
operator view of the group policy stays as saved."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import ingest, ml_false_positives, policies
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.redis_client import get_redis
from app.services import agent_policy

SHA = "ab" * 32
BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def api(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    async def redis():
        return evidence_api.redis

    async def audit(*a, **kw):
        evidence_api.audits.append(a)

    monkeypatch.setattr(policies, "audit_log", audit)
    monkeypatch.setattr(ml_false_positives, "audit_log", audit)
    app = FastAPI()
    for r in (policies.router, policies.agent_router, ingest.router, ml_false_positives.router):
        app.include_router(r)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_redis] = redis
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    agent_policy.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api
    agent_policy.invalidate()


async def test_only_fleet_wide_admins_change_the_list(api):
    c = api.api
    body = {"sha256": SHA.upper(), "engine": "ember2024_lgbm", "path": "C:\\Tools\\build.exe"}
    api.user = api.make_user(role="admin", group="blue", perms=("agents:manage",))
    assert (await c.post("/api/ml-false-positives", json=body)).status_code == 403  # one group's admin
    api.user = api.make_user(role="analyst", group="default", perms=("agents:read",))
    assert (await c.post("/api/ml-false-positives", json=body)).status_code == 403  # no permission
    assert (await c.get("/api/ml-false-positives")).json()["items"] == []  # anyone may look

    api.user = api.make_user(role="admin", group="default", perms=("agents:manage",))
    assert (await c.post("/api/ml-false-positives", json={"sha256": "abc"})).status_code == 422
    r = await c.post("/api/ml-false-positives", json=body)
    assert r.status_code == 201 and r.json()["sha256"] == SHA and r.json()["engine"] == "ember2024_lgbm"
    assert (await c.post("/api/ml-false-positives", json=body)).status_code == 201  # again: no-op
    assert [i["sha256"] for i in (await c.get("/api/ml-false-positives")).json()["items"]] == [SHA]
    assert [a[2] for a in api.audits] == ["ml_false_positive_added"]

    assert (await c.delete(f"/api/ml-false-positives/{SHA}")).status_code == 204
    assert (await c.delete(f"/api/ml-false-positives/{SHA}")).status_code == 404
    assert (await c.get("/api/ml-false-positives")).json()["items"] == []


async def test_agents_get_them_as_ml_exclusions(api):
    c = api.api
    hb = {"agent_id": str(api.agents["blue"]), "hostname": "blue-host"}
    v0 = (await c.post("/api/ingest/heartbeat", json=hb, headers=BLUE)).json()["policy_version"]

    api.user = api.make_user(role="superadmin", group="default", perms=())
    # the group already excludes one hash from ML, another only from the hash check
    other, hashonly = "cd" * 32, "ef" * 32
    await c.put("/api/policies/blue", json={"exclusions": [
        {"kind": "sha256", "value": other, "scopes": ["malware", "ml"]},
        {"kind": "sha256", "value": hashonly, "scopes": ["malware"]}]})
    for h in (SHA, other, hashonly):
        await c.post("/api/ml-false-positives", json={"sha256": h})
    agent_policy.invalidate()

    v1 = (await c.post("/api/ingest/heartbeat", json=hb, headers=BLUE)).json()["policy_version"]
    pol = (await c.post("/api/ingest/policy", headers=BLUE)).json()
    assert v1 != v0 and pol["version"] == v1
    excl = pol["settings"]["exclusions"]
    assert {"kind": "sha256", "value": SHA, "scopes": ["ml"], "comment": "ML false positive"} in excl
    assert [e["value"] for e in excl].count(other) == 1  # already excluded from ML there
    assert any(e["value"] == hashonly and e["scopes"] == ["ml"] for e in excl)
    # the operator still sees (and saves back) only the group's own exclusions
    view = (await c.get("/api/policies/blue")).json()
    assert [e["value"] for e in view["settings"]["exclusions"]] == [other, hashonly]
    assert view["version"] == v1

    # removing it changes the version again: agents put the file back under the model
    await c.delete(f"/api/ml-false-positives/{SHA}")
    agent_policy.invalidate()
    pol = (await c.post("/api/ingest/policy", headers=BLUE)).json()
    assert pol["version"] != v1 and SHA not in [e["value"] for e in pol["settings"]["exclusions"]]
