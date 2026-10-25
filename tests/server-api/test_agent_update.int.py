"""Agent self-update rollouts: signed package index, ring gating, offers in the
heartbeat, auto-pause on failed or stalled agents, retry, scoping."""
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class _Redis:
    """Enough of Redis for the heartbeat route."""

    def __init__(self):
        self.kv, self.items = {}, []

    async def xadd(self, *a, **kw):
        self.items.append(a)

    async def hgetall(self, key):
        return dict(self.kv.get(key) or {})

    async def hset(self, key, mapping):
        self.kv.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        pass

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True


def evidence_user(role, group, perms):
    return SimpleNamespace(id=uuid4(), group_id=group, username=role,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


PKG = b"pretend this is a .deb"


def sign(dir_, priv, version="2.0.0", os_="linux", arch="amd64", fmt="deb", name=None, body=PKG):
    name = name or {"deb": f"siem-agent_{version}_{arch}.deb", "msi": f"siem-agent-{version}-x64.msi"}[fmt]
    (dir_ / name).write_bytes(body)
    manifest = json.dumps({"schema": 1, "product": "siem-agent", "version": version, "os": os_, "arch": arch,
                           "format": fmt, "file": name, "sha256": hashlib.sha256(body).hexdigest(),
                           "size": len(body)}).encode()
    (dir_ / (name + ".sig")).write_text(json.dumps({
        "manifest": base64.b64encode(manifest).decode(),
        "signature": base64.b64encode(priv.sign(manifest)).decode(), "key_id": "test"}))
    return name


def pub_b64(priv):
    return base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def status(state="idle", kind="deb", target="", revision=0, attempts=0, error="", os_="linux", arch="amd64"):
    return {"kind": kind, "os": os_, "arch": arch, "state": state, "target": target, "revision": revision,
            "attempts": attempts, "error": error}


@pytest.fixture
async def env(monkeypatch, tmp_path):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs TEST_DATABASE_URL (disposable PostgreSQL)")
    import httpx
    from fastapi import FastAPI
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api.routes import agent_updates, ingest
    from app.core.config import settings
    from app.core.database import Base, get_db
    from app.core.deps import get_current_user
    from app.core.redis_client import get_redis
    from app.core.security import hash_token
    from app.models import models
    from app.services import agent_update

    monkeypatch.setattr(agent_update, "PACKAGES_DIR", tmp_path)
    monkeypatch.setattr(agent_update, "_cache", {})
    monkeypatch.setattr(settings, "AGENT_UPDATE_PUBLIC_KEYS", "")

    namespace = "agent_update_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as db:
        await db.execute(text("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public"))
        await db.execute(text(f'CREATE SCHEMA "{namespace}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{namespace},public"}},
                                 execution_options={"schema_translate_map": {None: namespace}})
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as db:
            await db.run_sync(Base.metadata.create_all)
        env = SimpleNamespace(sessions=sessions, dir=tmp_path, priv=Ed25519PrivateKey.generate(), redis=_Redis(),
                              audits=[], settings=settings, agents={})

        async def add_agent(name, group="blue", ring=2, version="1.9.0", **kw):
            async with sessions() as db:
                a = models.Agent(name=name, hostname=name, group_id=group, token_hash=hash_token(name + "-token"),
                                 approved=True, version=version, update_ring=ring, **kw)
                db.add(a)
                await db.commit()
                env.agents[name] = a.id
                return a.id
        env.add_agent = add_agent

        async def agent(name):
            async with sessions() as db:
                return await db.get(models.Agent, env.agents[name])
        env.agent = agent

        async def policy(group="blue"):
            async with sessions() as db:
                return await db.get(models.AgentUpdatePolicy, group)
        env.policy = policy

        env.user = evidence_user(role="admin", group="blue", perms=("agents:manage",))

        async def database():
            async with sessions() as db:
                yield db

        async def redis():
            return env.redis

        async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None):
            env.audits.append((action, resource_id, detail))

        app = FastAPI()
        app.include_router(ingest.router)
        app.include_router(agent_updates.router)
        app.dependency_overrides[get_db] = database
        app.dependency_overrides[get_redis] = redis
        app.dependency_overrides[get_current_user] = lambda: env.user
        monkeypatch.setattr(agent_updates, "audit_log", audit)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            env.client = client

            async def beat(name, version="1.9.0", update=None, **kw):
                body = {"agent_id": str(env.agents[name]), "version": version, **kw}
                if update is not None:
                    body["update"] = update
                r = await client.post("/api/ingest/heartbeat", json=body, headers={"X-Agent-Token": name + "-token"})
                assert r.status_code == 200, r.text
                return r.json()["update"]
            env.beat = beat
            yield env
    finally:
        await engine.dispose()
        async with admin.begin() as db:
            await db.execute(text(f'DROP SCHEMA "{namespace}" CASCADE'))
        await admin.dispose()


async def set_target(env, version="2.0.0", group="blue", **kw):
    return await env.client.put(f"/api/agent-updates/policies/{group}", json={"target_version": version, **kw})


async def test_offer_follows_rings_and_serves_the_signed_package(env):
    name = sign(env.dir, env.priv)
    await env.add_agent("canary", ring=0)
    await env.add_agent("web", ring=2)
    r = await set_target(env)
    assert r.status_code == 200, r.text
    assert r.json()["stage"] == 0 and r.json()["revision"] == 1

    offer = await env.beat("canary", update=status())
    assert offer["version"] == "2.0.0" and offer["revision"] == 1
    assert offer["url"] == f"/api/agent/update/package/{name}"
    assert offer["signed"]["signature"]
    assert await env.beat("web", update=status()) is None  # ring 2, stage 0

    pkg = await env.client.get(offer["url"], headers={"X-Agent-Token": "canary-token"})
    assert pkg.status_code == 200 and pkg.content == PKG
    assert (await env.client.get(offer["url"])).status_code == 401  # agent token required

    for stage in (1, 2):
        r = await env.client.post("/api/agent-updates/policies/blue/advance")
        assert r.status_code == 200 and r.json()["stage"] == stage
    assert (await env.client.post("/api/agent-updates/policies/blue/advance")).status_code == 409
    assert (await env.beat("web", update=status()))["version"] == "2.0.0"

    # updated: the next heartbeat on the target gets no offer, and progress says so
    assert await env.beat("canary", version="2.0.0", update=status(state="updated", target="2.0.0", revision=1)) is None
    p = (await env.client.get("/api/agent-updates/policies")).json()[0]["progress"]
    assert p["states"] == {"updated": 1, "pending": 1}
    assert [a[0] for a in env.audits] == ["agent_update_target_set", "agent_update_advance", "agent_update_advance"]


async def test_no_offer_when_it_should_not_update(env):
    sign(env.dir, env.priv)
    await env.add_agent("old")  # agents before self-update report no status
    await env.add_agent("zip", ring=0)
    await env.add_agent("arm", ring=0)
    await env.add_agent("isolated", ring=0, is_isolated=True)
    await env.add_agent("pending", ring=0)
    await set_target(env)
    await env.client.post("/api/agent-updates/policies/blue/advance")
    await env.client.post("/api/agent-updates/policies/blue/advance")
    assert await env.beat("old") is None
    assert await env.beat("zip", update=status(state="unsupported", kind="", error="agent not installed from the MSI")) is None
    assert await env.beat("arm", update=status(arch="arm64")) is None  # no signed arm64 package
    assert await env.beat("isolated", update=status()) is None
    await env.client.post("/api/agent-updates/policies/blue/pause")
    assert await env.beat("pending", update=status()) is None
    await env.client.post("/api/agent-updates/policies/blue/resume")
    assert (await env.beat("pending", update=status()))["version"] == "2.0.0"
    states = (await env.client.get("/api/agent-updates/policies")).json()[0]["progress"]["states"]
    assert states == {"not_reporting": 1, "unsupported": 1, "no_package": 1, "pending": 2}


async def test_failure_pauses_and_retry_starts_a_new_revision(env):
    sign(env.dir, env.priv)
    await env.add_agent("canary", ring=0)
    await env.add_agent("canary2", ring=0)
    await set_target(env)
    assert await env.beat("canary", update=status())
    assert await env.beat("canary", update=status("failed", target="2.0.0", revision=1, attempts=1,
                                                  error="dpkg: dependency problems")) is None
    p = await env.policy()
    assert p.paused and "dependency problems" in p.pause_reason and "canary" in p.pause_reason
    assert await env.beat("canary2", update=status()) is None  # paused for everyone
    assert (await env.client.post("/api/agent-updates/policies/blue/advance")).status_code == 409

    r = await env.client.post("/api/agent-updates/policies/blue/retry")
    assert r.json()["revision"] == 2 and not r.json()["paused"]
    offer = await env.beat("canary", update=status("failed", target="2.0.0", revision=1, attempts=1))
    assert offer["revision"] == 2  # the old revision's failure no longer counts
    assert not (await env.policy()).paused


async def test_max_failures_tolerates_some(env):
    sign(env.dir, env.priv)
    for n in ("a", "b", "c"):
        await env.add_agent(n, ring=0)
    await set_target(env, max_failures=2)
    await env.beat("a", update=status("failed", target="2.0.0", revision=1, error="x"))
    assert not (await env.policy()).paused
    await env.beat("b", update=status("failed", target="2.0.0", revision=1, error="y"))
    assert (await env.policy()).paused


async def test_stalled_agent_pauses_the_rollout(env):
    sign(env.dir, env.priv)
    long_ago = datetime.now(timezone.utc) - timedelta(minutes=20)
    await env.add_agent("gone", ring=0, last_seen_at=long_ago,
                        update_status=status("installing", target="2.0.0", revision=1, attempts=1))
    await env.add_agent("alive", ring=0)
    await set_target(env)
    assert await env.beat("alive", update=status()) is None  # the per-group check found the stall
    p = await env.policy()
    assert p.paused and "stalled" in p.pause_reason


async def test_new_target_restarts_at_ring_zero_and_needs_a_package(env):
    sign(env.dir, env.priv)
    sign(env.dir, env.priv, version="1.9.0")
    await set_target(env)
    await env.client.post("/api/agent-updates/policies/blue/advance")
    r = await set_target(env, "1.9.0")  # rollback is a new target
    assert r.json()["stage"] == 0 and r.json()["revision"] == 2
    r = await set_target(env, "3.0.0")
    assert r.status_code == 422
    assert (await set_target(env, "latest")).status_code == 422


async def test_rollback_to_an_archived_build(env):
    """publish-packages.sh moves earlier signed builds to archive/: still offered."""
    (env.dir / "archive").mkdir()
    old = sign(env.dir / "archive", env.priv, version="1.8.0")
    sign(env.dir, env.priv, version="1.9.0")
    await env.add_agent("canary", ring=0, version="1.9.0")
    assert (await set_target(env, "1.8.0")).status_code == 200
    offer = await env.beat("canary", version="1.9.0", update=status())
    assert offer["version"] == "1.8.0" and offer["url"].endswith("/" + old)
    pkg = await env.client.get(offer["url"], headers={"X-Agent-Token": "canary-token"})
    assert pkg.status_code == 200 and pkg.content == PKG
    listed = {p["version"]: p["archived"] for p in (await env.client.get("/api/agent-updates/packages")).json()}
    assert listed == {"1.9.0": False, "1.8.0": True}


async def test_server_keys_refuse_packages_they_do_not_verify(env):
    sign(env.dir, env.priv)
    other = Ed25519PrivateKey.generate()
    env.settings.AGENT_UPDATE_PUBLIC_KEYS = pub_b64(other)
    pkgs = (await env.client.get("/api/agent-updates/packages")).json()
    assert pkgs[0]["verified"] is False and "signed" not in pkgs[0]
    assert (await set_target(env)).status_code == 422
    await env.add_agent("canary", ring=0)
    assert (await env.client.get("/api/agent/update/package/siem-agent_2.0.0_amd64.deb",
                                 headers={"X-Agent-Token": "canary-token"})).status_code == 404

    env.settings.AGENT_UPDATE_PUBLIC_KEYS = "not-a-key"  # configured but unusable: nothing verifies
    assert (await env.client.get("/api/agent-updates/packages")).json()[0]["verified"] is False

    env.settings.AGENT_UPDATE_PUBLIC_KEYS = pub_b64(env.priv)
    assert (await env.client.get("/api/agent-updates/packages")).json()[0]["verified"] is True
    assert (await set_target(env)).status_code == 200


async def test_package_index_ignores_mismatched_and_unsigned_files(env):
    sign(env.dir, env.priv)
    (env.dir / "siem-agent_2.1.0_amd64.deb").write_bytes(PKG)  # no .sig
    name = sign(env.dir, env.priv, version="2.2.0")
    (env.dir / name).write_bytes(PKG + b"!")  # replaced after signing: size differs
    assert [p["version"] for p in (await env.client.get("/api/agent-updates/packages")).json()] == ["2.0.0"]
    await env.add_agent("canary", ring=0)
    for f in ("siem-agent_2.1.0_amd64.deb", name, "../etc/passwd", "siem-agent_2.0.0_amd64.deb.sig"):
        r = await env.client.get(f"/api/agent/update/package/{f}", headers={"X-Agent-Token": "canary-token"})
        assert r.status_code == 404, f


async def test_scoping_and_permissions(env):
    sign(env.dir, env.priv)
    assert (await set_target(env, group="red")).status_code == 404  # blue admin, red group
    env.user = evidence_user(role="analyst", group="blue", perms=("agents:read",))
    assert (await set_target(env)).status_code == 403
    env.user = evidence_user(role="superadmin", group="blue", perms=())
    assert (await set_target(env, group="red")).status_code == 200
    env.user = evidence_user(role="admin", group="blue", perms=("agents:manage",))
    assert (await env.client.get("/api/agent-updates/policies")).json() == []
    assert (await env.client.post("/api/agent-updates/policies/red/pause")).status_code == 404
    assert (await env.client.delete("/api/agent-updates/policies/red")).status_code == 404


async def test_unapproved_agent_cannot_download(env):
    sign(env.dir, env.priv)
    await env.add_agent("waiting", ring=0)
    async with env.sessions() as db:
        from app.models.models import Agent
        a = await db.get(Agent, env.agents["waiting"])
        a.approved = False
        await db.commit()
    r = await env.client.get("/api/agent/update/package/siem-agent_2.0.0_amd64.deb",
                             headers={"X-Agent-Token": "waiting-token"})
    assert r.status_code == 403
    await set_target(env)
    assert await env.beat("waiting", update=status()) is None


async def test_invalid_update_status_does_not_fail_the_heartbeat(env):
    await env.add_agent("weird", ring=0)
    assert await env.beat("weird", update={"state": "exploded"}) is None
    assert (await env.agent("weird")).update_status is None
