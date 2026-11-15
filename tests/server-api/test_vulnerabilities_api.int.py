"""Vulnerabilities API (routes/vulnerabilities.py): CVEs ranked KEV first,
then EPSS, then CVSS; one row per CVE with its hosts and fixes; resolved
findings and other groups left out; filters; per-CVE hosts; sync queued."""
import asyncio
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import vulnerabilities as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import CveIntel, HostVulnerability


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


class FakeRedis:
    def __init__(self):
        self.h, self.lists = {}, {}

    async def hgetall(self, k):
        return dict(self.h.get(k, {}))

    async def hset(self, k, mapping):
        self.h.setdefault(k, {}).update(mapping)

    async def rpush(self, k, v):
        self.lists.setdefault(k, []).append(v)


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    redis = FakeRedis()
    redis.h[routes.SCAN_STATE_KEY] = {"status": "ok", "hosts": "2"}

    async def get_redis():
        return redis

    monkeypatch.setattr(routes, "get_redis", get_redis)
    evidence_api.fake_redis = redis
    evidence_api.user = evidence_api.make_user(perms=("alerts:read", "agents:manage"))
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


def _row(agent, host, cve, package, **kw):
    agent_id, group = agent
    return HostVulnerability(agent_id=agent_id, group_id=group, hostname=host, cve_id=cve, package=package,
                             source=kw.pop("source", "osv"), first_seen=datetime.now(timezone.utc), **kw)


async def _seed(env):
    from uuid import uuid4

    from app.models.models import Agent
    blue = (env.agents["blue"], "blue")
    red = (env.agents["red"], "red")
    async with env.sessions() as db:
        second = Agent(name="win-02", hostname="win-02", group_id="blue", token_hash=uuid4().hex, approved=True,
                       status="online")
        db.add(second)
        await db.flush()
        blue2 = (second.id, "blue")
        db.add_all([
            # severe on paper, nobody exploits it
            _row(blue, "web-01", "CVE-2026-1", "openssl", cvss=9.8, severity="critical", fixed_version="3.0.2-1.9"),
            # medium, but on the KEV list, on two hosts
            _row(blue, "win-01", "CVE-2026-2", "Windows", source="msrc", cvss=5.5, severity="medium", kb="KB5127648"),
            _row(blue2, "win-02", "CVE-2026-2", "Windows", source="msrc", cvss=5.5, severity="medium", kb="KB5127648"),
            # likely to be exploited soon
            _row(blue, "web-01", "CVE-2026-3", "nginx", cvss=6.1, severity="medium", fixed_version="1.24.0-2"),
            # patched already
            _row(blue, "web-01", "CVE-2026-4", "bash", cvss=9.0, resolved_at=datetime.now(timezone.utc)),
            # another group's host
            _row(red, "red-01", "CVE-2026-5", "sudo", cvss=7.8),
            CveIntel(cve_id="CVE-2026-1", epss=0.0004, epss_percentile=0.1),
            CveIntel(cve_id="CVE-2026-2", epss=0.002, kev=True, kev_name="Windows Kernel EoP", kev_due_date="2026-12-01",
                     kev_ransomware=True),
            CveIntel(cve_id="CVE-2026-3", epss=0.35, epss_percentile=0.97),
        ])
        await db.commit()


async def test_ranked_kev_then_epss_then_cvss(env):
    await _seed(env)
    r = await env.api.get("/api/vulnerabilities")
    assert r.status_code == 200, r.text
    out = r.json()
    assert [(i["cve_id"], i["priority"]) for i in out["items"]] == [
        ("CVE-2026-2", "critical"), ("CVE-2026-3", "high"), ("CVE-2026-1", "medium")]
    kev = out["items"][0]
    assert (kev["hosts"], kev["hostnames"], kev["fixes"], kev["kev_due_date"], kev["kev_ransomware"], kev["title"]) == \
        (2, ["win-01", "win-02"], ["KB5127648"], "2026-12-01", True, "Windows Kernel EoP")
    assert out["items"][1]["fixes"] == ["nginx 1.24.0-2"] and "agent_ids" not in kev
    assert out["summary"] == {"cves": 3, "by_priority": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                              "kev": 1, "hosts": 2}  # hosts are agents: web-01/win-01 rows share one
    assert out["scan"] == {"status": "ok", "hosts": "2"}


async def test_filters_and_per_cve_hosts(env):
    await _seed(env)
    assert [i["cve_id"] for i in (await env.api.get("/api/vulnerabilities", params={"kev": "true"})).json()["items"]] == \
        ["CVE-2026-2"]
    assert [i["cve_id"] for i in (await env.api.get("/api/vulnerabilities", params={"priority": "high"})).json()["items"]] == \
        ["CVE-2026-3"]
    assert [i["cve_id"] for i in (await env.api.get("/api/vulnerabilities", params={"q": "openssl"})).json()["items"]] == \
        ["CVE-2026-1"]
    by_host = (await env.api.get("/api/vulnerabilities", params={"agent_id": str(env.agents["blue"])})).json()
    assert by_host["summary"]["cves"] == 3
    hosts = (await env.api.get("/api/vulnerabilities/cve-2026-2/hosts")).json()
    assert [(h["hostname"], h["kb"]) for h in hosts] == [("win-01", "KB5127648"), ("win-02", "KB5127648")]
    # resolved and other groups' findings are not there
    assert (await env.api.get("/api/vulnerabilities/CVE-2026-4/hosts")).status_code == 404
    assert (await env.api.get("/api/vulnerabilities/CVE-2026-5/hosts")).status_code == 404


async def test_sync_queues_intel_and_scan(env):
    assert (await env.api.post("/api/vulnerabilities/sync")).status_code == 202
    assert env.fake_redis.lists == {routes.INTEL_SYNC_QUEUE: ["1"], routes.SCAN_QUEUE: ["1"]}
    env.user = env.make_user(perms=("alerts:read",))
    assert (await env.api.post("/api/vulnerabilities/sync")).status_code == 403
