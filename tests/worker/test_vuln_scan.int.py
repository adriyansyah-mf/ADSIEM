"""Vulnerability scan against PostgreSQL: intel stores (KEV, EPSS, Microsoft
fixes), a Windows host matched by build and UBR, a Linux host matched through
OSV (faked) by source package, findings resolved when patched and reopened
when back, and one alert per host for newly found KEV CVEs. Needs
TEST_DATABASE_URL (disposable PostgreSQL); each test gets its own schema."""
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from worker import vuln_intel, vuln_scan
from app.models.models import HygieneSnapshot  # a full report row (the worker reads a few columns)
from worker.models import CveIntel, HostVulnerability, MsrcFix


@pytest.fixture
async def sessions(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    from app.core.database import Base
    from app.models import models as api

    schema = "vuln_test_" + uuid.uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    tables = {api.HygieneSnapshot.__table__, api.CveIntel.__table__, api.MsrcFix.__table__,
              api.HostVulnerability.__table__}
    while True:
        deps = {fk.column.table for t in tables for fk in t.foreign_keys}
        if deps <= tables:
            break
        tables |= deps
    async with engine.begin() as c:
        await c.run_sync(lambda conn: Base.metadata.create_all(conn, tables=list(tables)))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(vuln_intel, "AsyncSessionLocal", factory)
    monkeypatch.setattr(vuln_scan, "AsyncSessionLocal", factory)
    try:
        yield factory
    finally:
        await engine.dispose()
        async with admin.begin() as c:
            await c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


class FakeRedis:
    def __init__(self):
        self.kv, self.h, self.lists = {}, {}, {}

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v, ex=None, nx=False):
        if nx and k in self.kv:
            return False
        self.kv[k] = v
        return True

    async def hset(self, k, field=None, value=None, mapping=None):
        self.h.setdefault(k, {}).update(mapping or {field: value})

    async def hgetall(self, k):
        return dict(self.h.get(k, {}))


class FakeResponse:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


class FakeOSV:
    """querybatch + vulns/{id}; records what was asked."""
    def __init__(self, known):
        self.known, self.queries, self.gets = known, [], []

    async def post(self, url, json):
        self.queries += [(q["package"]["ecosystem"], q["package"]["name"], q["version"]) for q in json["queries"]]
        return FakeResponse({"results": [
            {"vulns": [{"id": vid} for vid in self.known.get((q["package"]["name"], q["version"]), {})]}
            for q in json["queries"]]})

    async def get(self, url):
        vid = url.rsplit("/", 1)[1]
        self.gets.append(vid)
        for recs in self.known.values():
            if vid in recs:
                return FakeResponse(recs[vid])
        return FakeResponse({}, 404)


async def _agent(sessions, name, group="blue"):
    from app.models.models import Agent  # the full row (the worker's model maps a few columns)
    async with sessions() as db:
        a = Agent(id=uuid.uuid4(), name=name, hostname=name, group_id=group, token_hash=uuid.uuid4().hex,
                  approved=True, status="online")
        db.add(a)
        await db.commit()
        return a.id


async def _snapshot(sessions, agent_id, name, **kw):
    async with sessions() as db:
        s = HygieneSnapshot(agent_id=agent_id, hostname=name, group_id="blue",
                            collected_at=datetime.now(timezone.utc), **kw)
        db.add(s)
        await db.commit()
        return s


async def _open(sessions, agent_id):
    async with sessions() as db:
        rows = (await db.execute(select(HostVulnerability).where(HostVulnerability.agent_id == agent_id))).scalars()
        return {(r.cve_id, r.package): r for r in rows}


async def test_intel_stores_upsert_and_unflag(sessions):
    await vuln_intel.store_kev([{"cve_id": "CVE-2024-1", "kev": True, "kev_name": "One", "kev_date_added": "2024-01-02",
                                 "kev_due_date": "2024-01-23", "kev_ransomware": False},
                                {"cve_id": "CVE-2024-2", "kev": True, "kev_name": "Two", "kev_date_added": None,
                                 "kev_due_date": None, "kev_ransomware": True}])
    await vuln_intel.store_epss([{"cve_id": "CVE-2024-1", "epss": 0.5, "epss_percentile": 0.98},
                                 {"cve_id": "CVE-2024-3", "epss": 0.001, "epss_percentile": 0.2}])
    # next day CVE-2024-2 left the catalogue
    await vuln_intel.store_kev([{"cve_id": "CVE-2024-1", "kev": True, "kev_name": "One", "kev_date_added": "2024-01-02",
                                 "kev_due_date": "2024-01-23", "kev_ransomware": False}])
    async with sessions() as db:
        rows = {r.cve_id: r for r in (await db.execute(select(CveIntel))).scalars()}
    assert (rows["CVE-2024-1"].kev, rows["CVE-2024-1"].epss) == (True, 0.5)  # both feeds on one row
    assert rows["CVE-2024-2"].kev is False and rows["CVE-2024-3"].kev is False


async def test_a_later_release_keeps_the_later_fix(sessions):
    row = {"cve_id": "CVE-2026-1", "build": "10.0.26100", "edition": "client", "kb": "KB1", "severity": "high",
           "cvss": 7.8, "impact": None, "title": "t"}
    await vuln_intel.store_msrc("2026-Sep", [{**row, "fixed_ubr": 9000, "release": "2026-Sep"}])
    await vuln_intel.store_msrc("2026-Oct", [{**row, "fixed_ubr": 9711, "kb": "KB2", "release": "2026-Oct"}])
    await vuln_intel.store_msrc("2026-Sep", [{**row, "fixed_ubr": 9000, "release": "2026-Sep"}])  # Sep revised
    async with sessions() as db:
        fixes = (await db.execute(select(MsrcFix))).scalars().all()
    assert [(f.fixed_ubr, f.kb, f.release) for f in fixes] == [(9711, "KB2", "2026-Oct")]
    await vuln_intel.drop_old_msrc(["2026-Nov"])
    async with sessions() as db:
        assert (await db.execute(select(MsrcFix))).scalars().all() == []


async def test_windows_host_by_build_ubr_and_edition(sessions, monkeypatch):
    alerts = []

    async def create_alert(rule_match, *args):
        alerts.append((rule_match, args))

    from worker import alert_manager
    monkeypatch.setattr(alert_manager, "create_alert", create_alert)
    async with sessions() as db:
        db.add_all([
            MsrcFix(cve_id="CVE-2026-10", build="10.0.26100", edition="client", fixed_ubr=9711, kb="KB5127648",
                    severity="high", cvss=7.8, impact="Elevation of Privilege", title="Kernel EoP", release="2026-Oct"),
            MsrcFix(cve_id="CVE-2026-11", build="10.0.26100", edition="client", fixed_ubr=9445, kb="KB5124008",
                    severity="critical", cvss=9.8, title="old", release="2026-Sep"),
            MsrcFix(cve_id="CVE-2026-12", build="10.0.26100", edition="server", fixed_ubr=33650, kb="KB5126646",
                    severity="high", cvss=8.8, title="server only", release="2026-Oct"),
            CveIntel(cve_id="CVE-2026-10", kev=True, kev_name="Kernel EoP"),
        ])
        await db.commit()
    agent = await _agent(sessions, "win11")
    snap = await _snapshot(sessions, agent, "win11", os_name="Windows 11 Pro", os_version="24H2",
                           kernel="10.0.26100.9500", packages=[])
    redis = FakeRedis()
    out = await vuln_scan.scan_once(redis)
    found = await _open(sessions, agent)
    assert list(found) == [("CVE-2026-10", "Windows")]  # 9445 is installed already; the server fix is not ours
    row = found[("CVE-2026-10", "Windows")]
    assert (row.kb, row.fixed_version, row.source, row.resolved_at) == ("KB5127648", "10.0.26100.9711", "msrc", None)
    assert out["hosts"] == 1 and out["kev_alerts"] == 1
    rule, args = alerts[0]
    assert rule["title"] == vuln_scan.KEV_ALERT_TITLE and rule["matched_fields"]["cve"] == ["CVE-2026-10"]
    assert args[1] == agent and args[2] == "blue"

    # patched: resolved, and no second alert
    async with sessions() as db:
        await db.execute(text("UPDATE hygiene_snapshots SET kernel = '10.0.26100.9711'"))
        await db.commit()
    await vuln_scan.scan_once(redis)
    assert (await _open(sessions, agent))[("CVE-2026-10", "Windows")].resolved_at is not None
    assert len(alerts) == 1


async def test_linux_host_through_osv_by_source_package(sessions, monkeypatch):
    record = {"id": "UBUNTU-CVE-2023-0464", "upstream": ["CVE-2023-0464"], "summary": "openssl: resource use",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
              "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.9"}]}]}]}
    osv = FakeOSV({("openssl", "3.0.2-0ubuntu1.8"): {"UBUNTU-CVE-2023-0464": record}})

    class Client:
        async def __aenter__(self):
            return osv

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(vuln_scan.httpx, "AsyncClient", lambda **kw: Client())
    agent = await _agent(sessions, "web-01")
    packages = [{"name": "libssl3", "version": "3.0.2-0ubuntu1.8", "source": "dpkg", "source_name": "openssl"},
                {"name": "openssl", "version": "3.0.2-0ubuntu1.8", "source": "dpkg", "source_name": "openssl"},
                {"name": "bash", "version": "5.1-6ubuntu1", "source": "dpkg"}]
    await _snapshot(sessions, agent, "web-01", os_name="Ubuntu", os_version="22.04", kernel="5.15.0", packages=packages)
    redis = FakeRedis()
    await vuln_scan.scan_once(redis)
    found = await _open(sessions, agent)
    assert list(found) == [("CVE-2023-0464", "openssl")]
    row = found[("CVE-2023-0464", "openssl")]
    assert (row.installed_version, row.fixed_version, row.cvss, row.severity) == \
        ("3.0.2-0ubuntu1.8", "3.0.2-0ubuntu1.9", 7.5, "high")
    # one lookup per source package and version, in the host's own release
    assert sorted(osv.queries) == [("Ubuntu:22.04:LTS", "bash", "5.1-6ubuntu1"),
                                   ("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.8")]
    # a second scan is served from the cache
    osv.queries.clear()
    osv.gets.clear()
    await vuln_scan.scan_once(redis)
    assert osv.queries == [] and osv.gets == []


async def test_a_stale_snapshot_is_not_scanned(sessions):
    agent = await _agent(sessions, "old")
    async with sessions() as db:
        db.add(HygieneSnapshot(agent_id=agent, hostname="old", group_id="blue", os_name="Windows 11 Pro",
                               kernel="10.0.26100.1", collected_at=datetime.now(timezone.utc) - timedelta(days=10)))
        await db.commit()
    assert (await vuln_scan.scan_once(FakeRedis()))["hosts"] == 0
