"""Period summary (routes/reports.py, services/periodic_report.py): the numbers
of a date range against the range before it, by day in the viewer's time zone,
the PDF with an AI summary, kept in a history, all within the caller's group."""
import asyncio
from datetime import date, datetime, time, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import reports
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import Alert, Case, CveIntel, HostVulnerability

TODAY = date(2026, 11, 16)


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


def _person(group="blue"):
    return SimpleNamespace(id=uuid4(), username=f"ana-{group}", group_id=group,
                           role=SimpleNamespace(name="analyst", permissions=[SimpleNamespace(name="alerts:read")]))


def _at(day: date, hour: int) -> datetime:
    return datetime.combine(day, time(hour), tzinfo=timezone.utc)


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    evidence_api.prompts = []

    async def fake_llm(api_key, model, prompt, max_tokens=1500, *, db=None):
        evidence_api.prompts.append(prompt)
        return "Periode ini tenang.\n\nSatu kasus kritis.\n\nTambal KEV."
    monkeypatch.setattr(reports, "generate_text", fake_llm)

    async def no_audit(*a, **kw):
        return None
    monkeypatch.setattr(reports, "audit_log", no_audit)

    blue = evidence_api.agents["blue"]
    async with evidence_api.sessions() as db:
        week = [TODAY - timedelta(days=i) for i in range(7)]
        for i, day in enumerate(week):  # this week: 7 alerts, 2 critical
            db.add(Alert(title="SSH brute force" if i % 2 else "Webshell upload", group_id="blue", agent_id=blue,
                         severity="critical" if i < 2 else "medium", hostname="web-01", source_ip="45.129.56.138",
                         mitre_techniques=["T1110"] if i % 2 else ["T1505.003"], created_at=_at(day, 10),
                         acknowledged_at=_at(day, 10) + timedelta(minutes=30), resolved_at=_at(day, 12),
                         ai_verdict="create_case" if i < 2 else "monitor"))
        for i in range(14):  # the week before: 14 alerts
            db.add(Alert(title="Port scan", group_id="blue", severity="low", hostname="db-01",
                         created_at=_at(TODAY - timedelta(days=7 + i % 7), 9)))
        db.add(Alert(title="Other group", group_id="red", severity="critical", created_at=_at(TODAY, 8)))
        db.add(Case(title="Webshell on web-01", severity="critical", status="open", group_id="blue", created_at=_at(TODAY, 11)))
        db.add(Case(title="Brute force", severity="medium", status="resolved", group_id="blue",
                    created_at=_at(TODAY - timedelta(days=9), 11), updated_at=_at(TODAY - timedelta(days=1), 11)))
        db.add(CveIntel(cve_id="CVE-2024-3400", kev=True, kev_name="PAN-OS command injection", epss=0.9))
        db.add(HostVulnerability(agent_id=blue, group_id="blue", hostname="web-01", cve_id="CVE-2024-3400",
                                 source="osv", package="pan-os", severity="critical"))
        await db.commit()

    app = FastAPI()
    app.include_router(reports.router)
    app.dependency_overrides[get_db] = database
    evidence_api.user = _person()
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


PERIOD = {"date_from": (TODAY - timedelta(days=6)).isoformat(), "date_to": TODAY.isoformat()}


async def test_summary_compares_with_the_period_before(env):
    r = await env.api.get("/api/reports/summary", params={**PERIOD, "tz": "UTC"})
    assert r.status_code == 200, r.text
    s = r.json()
    a = s["alerts"]
    assert (a["total"], a["previous"], a["change_pct"]) == (7, 14, -50.0)
    assert a["by_severity"] == {"critical": 2, "medium": 5}
    assert len(a["by_day"]) == 7 and sum(d["total"] for d in a["by_day"]) == 7
    assert a["by_day"][-1] == {"day": TODAY.isoformat(), "total": 1, "critical": 1, "high": 0}
    assert a["top_rules"][0] == {"name": "Webshell upload", "count": 4}
    assert a["top_hosts"] == [{"name": "web-01", "count": 7}]
    assert {m["technique"] for m in s["mitre"]} == {"T1110", "T1505.003"}
    assert a["mtta_minutes"] == 30.0 and a["mttr_minutes"] == 120.0
    assert a["ai_verdicts"] == {"create_case": 2, "monitor": 5}
    assert s["cases"]["opened"] == 1 and s["cases"]["closed"] == 1 and s["cases"]["open_now"] == 1
    assert s["cases"]["notable"][0]["title"] == "Webshell on web-01"
    assert s["vulnerabilities"]["kev_open"] == 1 and s["vulnerabilities"]["top_kev"][0]["cve_id"] == "CVE-2024-3400"
    assert s["agents"]["total"] == 1  # the blue agent only

    jakarta = (await env.api.get("/api/reports/summary", params={**PERIOD, "tz": "Asia/Jakarta"})).json()
    assert jakarta["period"]["tz"] == "Asia/Jakarta" and jakarta["alerts"]["total"] == 7


async def test_generate_stores_the_pdf_in_the_history(env):
    r = await env.api.post("/api/reports/generate", json={**PERIOD, "language": "id", "tz": "Asia/Jakarta"})
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF") and r.headers["x-report-id"]
    assert "Bahasa Indonesia" in env.prompts[0] and "<period_data>" in env.prompts[0]
    no_ai = await env.api.post("/api/reports/generate", json={**PERIOD, "language": "English", "use_ai": False})
    assert no_ai.status_code == 200 and len(env.prompts) == 1

    history = (await env.api.get("/api/reports/history")).json()
    assert len(history) == 2 and history[0]["ai"] is False and history[1]["ai"] is True
    assert history[1]["language"] == "id" and history[1]["alerts"] == 7
    again = await env.api.get(f"/api/reports/history/{r.headers['x-report-id']}/pdf")
    assert again.content == r.content

    env.user = _person("red")
    assert (await env.api.get("/api/reports/history")).json() == []
    assert (await env.api.get(f"/api/reports/history/{r.headers['x-report-id']}/pdf")).status_code == 404
    red = (await env.api.get("/api/reports/summary", params=PERIOD)).json()
    assert red["alerts"]["total"] == 1


async def test_bad_ranges_are_refused(env):
    r = await env.api.get("/api/reports/summary", params={"date_from": TODAY.isoformat(),
                                                          "date_to": (TODAY - timedelta(days=1)).isoformat()})
    assert r.status_code == 422
    r = await env.api.get("/api/reports/summary", params={"date_from": "2024-01-01", "date_to": TODAY.isoformat()})
    assert r.status_code == 422
