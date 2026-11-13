# tests/worker/test_lateral.int.py
"""Lateral movement edges in PostgreSQL (worker/worker/lateral.py): learning
period, new paths, write gate, users, fan-out, chains and address → host."""
import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import LateralEdge
from worker import lateral

HOUR = 3600


@pytest.fixture(autouse=True)
def _loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


class FakeRedis:
    def __init__(self):
        self.kv, self.sets, self.stream = {}, {}, []

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def get(self, key):
        return self.kv.get(key)

    async def expire(self, key, seconds):
        return True

    async def sadd(self, key, member):
        self.sets.setdefault(key, set()).add(member)

    async def scard(self, key):
        return len(self.sets.get(key, ()))

    async def xadd(self, stream, data):
        self.stream.append(data)

    def forget_touches(self):
        for k in [k for k in self.kv if k.startswith("siem:lat:touch:")]:
            del self.kv[k]


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
async def env(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "lateral_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[LateralEdge.__table__]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setting(key, default=""):
        return default
    monkeypatch.setattr(lateral.settings_cache, "get_setting", setting)
    try:
        yield sessions
    finally:
        await engine.dispose()
        async with admin.begin() as c:
            await c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def edges(sessions):
    async with sessions() as db:
        return {(e.src, e.dst, e.protocol): e for e in (await db.execute(select(LateralEdge))).scalars()}


async def test_learning_then_new_paths_users_and_gate(env):
    r, clock = FakeRedis(), Clock()
    lat = lateral.Lateral(r, env, now=clock)
    assert await lat.observe("blue", "web-01", "db-01", "ssh", "deploy") == []  # learning
    clock.t += 73 * HOUR
    assert await lat.observe("blue", "web-01", "db-01", "ssh", "deploy") == []  # touched within 5 min
    r.forget_touches()
    assert await lat.observe("blue", "web-01", "db-01", "ssh", "root") == []    # known path, new user
    found = await lat.observe("blue", "web-01", "fs-01", "smb")
    assert found == [("behavior_lateral_new_path", {"src": "web-01", "dst": "fs-01", "protocol": "smb", "user": ""})]
    e = (await edges(env))[("web-01", "db-01", "ssh")]
    assert e.count == 2 and e.users == ["deploy", "root"]


async def test_fanout_and_chain(env):
    r, clock = FakeRedis(), Clock()
    lat = lateral.Lateral(r, env, now=clock)
    await lat.observe("blue", "seed", "seed-2", "ssh")  # starts the group's learning clock
    clock.t += 73 * HOUR
    events = []
    for i in range(5):
        events += [e for e, _ in await lat.observe("blue", "web-01", f"ws-{i}", "smb")]
    assert events.count("behavior_lateral_new_path") == 5 and events.count("behavior_lateral_fanout") == 1
    # ws-0 was just reached by a new path; its own new path to dc-01 is a chain
    found = await lat.observe("blue", "ws-0", "dc-01", "rdp", "admin")
    chain = [f for e, f in found if e == "behavior_lateral_chain"]
    assert chain and chain[0]["path"] == "web-01 -> ws-0 -> dc-01"


async def test_addresses_become_hostnames_and_findings_reach_the_stream(env):
    r = FakeRedis()
    r.kv["siem:lat:group:blue:first"] = str(1.0)  # learnt long ago
    # db-01's agent reports its own address on an outbound connection
    await lateral.observe(r, log_type="linux_network_connect", group_id="blue", hostname="db-01", sessions=env,
                          decoded={"source.address": "10.0.0.20", "destination.address": "8.8.8.8",
                                   "destination.port": "443", "process.name": "curl"})
    # web-01 then opens SMB to 10.0.0.20: the path is web-01 → db-01
    pushed = await lateral.observe(r, log_type="windows_etw_network", group_id="blue", hostname="web-01", sessions=env,
                                   decoded={"Initiated": "true", "SourceIp": "10.0.0.10", "destination.ip": "10.0.0.20",
                                            "destination.port": "445", "Image": "C:\\Windows\\System32\\cmd.exe"})
    assert pushed == ["behavior_lateral_new_path"] and ("web-01", "db-01", "smb") in await edges(env)
    assert r.stream[0]["raw_message"].startswith("event=behavior_lateral_new_path src=web-01 dst=db-01 protocol=smb")
    # a login from web-01's address to db-01 is the same hop seen from the other side
    pushed = await lateral.observe(r, log_type="windows_security", group_id="blue", hostname="db-01", sessions=env,
                                   decoded={"event.action": "login_success", "source.ip": "10.0.0.10",
                                            "user.name": "admin", "winlog.logon.type": "10"})
    assert ("web-01", "db-01", "rdp") in await edges(env) and pushed == ["behavior_lateral_new_path"]
    # external destinations and non-admin ports are not lateral movement
    assert await lateral.observe(r, log_type="linux_network_connect", group_id="blue", hostname="db-01", sessions=env,
                                 decoded={"destination.address": "10.0.0.30", "destination.port": "5432",
                                          "process.name": "psql"}) == []
