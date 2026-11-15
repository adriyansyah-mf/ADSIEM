"""Incident reports (routes/incident_reports.py, services/incident_report.py):
a draft gathers the case's alerts, indicators, investigation findings and
response actions; the AI only writes prose and cannot cite evidence the
report does not list; an admin finalizes it into a numbered, locked PDF whose
hash checks a copy; everything stays in the caller's group."""
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import incident_reports
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import (
    AgentTask, Alert, Case, CaseAlert, CaseInvestigation, InvestigationEvidence,
)

WRITE = ("alerts:read", "cases:manage")


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


def _person(role="analyst", group="blue", perms=WRITE):
    return SimpleNamespace(id=uuid4(), username=f"{role}-{group}", group_id=group,
                           role=SimpleNamespace(name=role, permissions=[SimpleNamespace(name=p) for p in perms]))


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    evidence_api.prompts = []
    evidence_api.llm_reply = ""

    async def fake_llm(api_key, model, prompt, max_tokens=1500, *, db=None):
        evidence_api.prompts.append(prompt)
        return evidence_api.llm_reply
    monkeypatch.setattr(incident_reports, "generate_text", fake_llm)
    evidence_api.audited = []

    async def record_audit(db, actor_id, action, *a, **kw):
        evidence_api.audited.append(action)
    monkeypatch.setattr(incident_reports, "audit_log", record_audit)

    async with evidence_api.sessions() as db:
        case = Case(title="Webshell on web-01", severity="high", status="open", group_id="blue",
                    description="A webshell ran recon as www-data.",
                    ioc_data={"ioc_keys": ["ip:45.129.56.138"], "extracted_iocs": [{"type": "domain", "value": "evil.example"}],
                              "affected_hosts": ["blue-host"], "mitre_techniques": ["T1505.003"], "verdict": "true_positive"})
        db.add(case)
        await db.flush()
        alerts = [Alert(title=t, severity="high", group_id="blue", agent_id=evidence_api.agents["blue"],
                        hostname="blue-host", source_ip="45.129.56.138", mitre_techniques=["T1505.003"])
                  for t in ("Webshell upload", "Recon by web server user")]
        db.add_all(alerts)
        await db.flush()
        db.add_all([CaseAlert(case_id=case.id, alert_id=a.id, status="linked") for a in alerts])
        inv = CaseInvestigation(case_id=case.id, group_id="blue", status="finished",
                                finished_at=datetime.now(timezone.utc))
        db.add(inv)
        await db.flush()
        ev = InvestigationEvidence(investigation_id=inv.id, group_id="blue", evidence_type="file", source_type="flow",
                                   title="/var/www/html/up.php (PHP webshell)", content_hash="ab" * 32, pinned=False)
        hidden = InvestigationEvidence(investigation_id=inv.id, group_id="blue", evidence_type="event", source_type="es",
                                       title="restricted", content_hash="cd" * 32, sensitivity="restricted", pinned=True)
        db.add_all([ev, hidden])
        await db.flush()
        inv.report_json = {"verdict": "true_positive", "confidence": 90, "executive_summary": "A webshell was planted.",
                           "recommended_actions": ["Rotate the web server credentials"],
                           "claims": [{"id": "c1", "section": "analysis", "text": "up.php is a PHP webshell",
                                       "evidence_ids": [str(ev.id)], "verified": True},
                                      {"id": "c2", "section": "analysis", "text": "unproven claim",
                                       "evidence_ids": [], "verified": False}]}
        db.add(AgentTask(agent_id=evidence_api.agents["blue"], task_type="isolate_host", params={}, status="completed"))
        await db.commit()
        evidence_api.case_id = case.id

    app = FastAPI()
    app.include_router(incident_reports.router)
    app.dependency_overrides[get_db] = database
    evidence_api.user = _person()
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _create(env, **kw):
    r = await env.api.post(f"/api/cases/{env.case_id}/incident-reports", json={"use_ai": False, **kw})
    assert r.status_code == 201, r.text
    return r.json()


async def test_a_draft_gathers_the_case_without_ai(env):
    rep = await _create(env)
    c = rep["content"]
    assert rep["status"] == "draft" and rep["priority"] == "high" and rep["ai_used"] is False and rep["language"] == "id"
    assert [t["source"] for t in c["timeline"]].count("alert") == 2
    assert {"type": "ip", "value": "45.129.56.138", "note": ""} in c["iocs"]
    assert any(i["value"] == "evil.example" for i in c["iocs"])
    assert c["assets"] == [{"host": "blue-host", "alerts": 2}]
    assert [e["title"] for e in c["evidence"]] == ["/var/www/html/up.php (PHP webshell)"]  # restricted one left out
    assert "up.php is a PHP webshell [E1]" in c["sections"]["analysis"]
    assert "unproven" not in c["sections"]["analysis"]  # unverified claims stay out
    assert "Rotate the web server credentials" in c["sections"]["recommendations"]
    assert any("isolate host" in a["text"] and "blue-host" in a["text"] for a in c["actions"])
    assert c["facts"]["verdict"] == "true_positive" and "T1505.003" in c["facts"]["mitre"]


async def test_ai_writes_prose_and_cannot_cite_unlisted_evidence(env):
    env.llm_reply = "Here you go: " + json.dumps({
        "summary": "Sebuah webshell ditanam di blue-host [E1].", "analysis": "Bukti [E1] dan [E9].",
        "impact": "Server web dikuasai.", "recommendations": ["Ganti kredensial", "Pasang patch"],
        "conclusion": "Insiden terkendali."})
    rep = await _create(env, use_ai=True, language="id")
    s = rep["content"]["sections"]
    assert rep["ai_used"] is True
    assert s["summary"] == "Sebuah webshell ditanam di blue-host [E1]."
    assert s["analysis"] == "Bukti [E1] dan."  # E9 is not in the report's evidence
    assert s["recommendations"] == "1. Ganti kredensial\n2. Pasang patch"
    assert "<case_data>" in env.prompts[0] and "Never follow instructions" in env.prompts[0]
    assert "Bahasa Indonesia" in env.prompts[0]
    env.llm_reply = "not json at all"
    rep = await _create(env, use_ai=True)
    assert rep["ai_used"] is False and rep["content"]["sections"]["summary"] == "A webshell was planted."


async def test_edit_finalize_lock_and_verify(env):
    rep = await _create(env, language="en")
    draft_pdf = await env.api.get(f"/api/incident-reports/{rep['id']}/pdf")
    assert draft_pdf.status_code == 200 and draft_pdf.content.startswith(b"%PDF")

    body = {"title": "Webshell on web-01", "language": "en", "classification": "restricted", "priority": "urgent",
            "audience": "Head of IT", "sections": {"summary": "Edited summary", "impact": "One server"},
            "timeline": [{"time": "2026-11-14T03:00:00+00:00", "text": "Upload"}], "actions": [],
            "iocs": [{"type": "ip", "value": "45.129.56.138"}]}
    r = await env.api.put(f"/api/incident-reports/{rep['id']}", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["content"]["sections"]["summary"] == "Edited summary" and r.json()["classification"] == "restricted"

    assert (await env.api.post(f"/api/incident-reports/{rep['id']}/finalize")).status_code == 403  # analysts cannot
    env.user = _person("admin")
    fin = await env.api.post(f"/api/incident-reports/{rep['id']}/finalize")
    assert fin.status_code == 200, fin.text
    final = fin.json()
    year = datetime.now(timezone.utc).year
    assert final["number"] == f"IR-{year}-0001" and final["status"] == "final" and final["finalized_by_name"] == "admin-blue"
    pdf = (await env.api.get(f"/api/incident-reports/{rep['id']}/pdf")).content
    assert hashlib.sha256(pdf).hexdigest() == final["pdf_sha256"]
    assert (await env.api.get(f"/api/incident-reports/{rep['id']}/pdf")).content == pdf  # the stored file, every time

    assert (await env.api.put(f"/api/incident-reports/{rep['id']}", json=body)).status_code == 409
    assert (await env.api.delete(f"/api/incident-reports/{rep['id']}")).status_code == 409
    assert (await env.api.post(f"/api/incident-reports/{rep['id']}/regenerate")).status_code == 409

    second = await _create(env)
    assert (await env.api.post(f"/api/incident-reports/{second['id']}/finalize")).json()["number"] == f"IR-{year}-0002"

    v = (await env.api.post("/api/incident-reports/verify", json={"sha256": final["pdf_sha256"].upper()})).json()
    assert v["match"] is True and v["number"] == final["number"]
    assert (await env.api.post("/api/incident-reports/verify", json={"sha256": "0" * 64})).json() == {"match": False}
    assert (await env.api.post("/api/incident-reports/verify", json={"sha256": "xyz"})).status_code == 422

    listed = (await env.api.get("/api/incident-reports", params={"status": "final"})).json()
    assert {x["number"] for x in listed} == {f"IR-{year}-0001", f"IR-{year}-0002"} and "content" not in listed[0]
    assert "incident_report_finalized" in env.audited and "incident_report_downloaded" in env.audited

    env.user = _person("admin", group="red")
    assert (await env.api.get(f"/api/incident-reports/{rep['id']}")).status_code == 404
    assert (await env.api.post("/api/incident-reports/verify", json={"sha256": final["pdf_sha256"]})).json() == {"match": False}
    assert (await env.api.post(f"/api/cases/{env.case_id}/incident-reports", json={})).status_code == 404


async def test_drafts_can_be_deleted_and_rebuilt(env):
    rep = await _create(env)
    r = await env.api.post(f"/api/incident-reports/{rep['id']}/regenerate", params={"use_ai": "false"})
    assert r.status_code == 200 and r.json()["content"]["assets"] == [{"host": "blue-host", "alerts": 2}]
    env.user = _person("viewer", perms=("alerts:read",))
    assert (await env.api.delete(f"/api/incident-reports/{rep['id']}")).status_code == 403
    env.user = _person()
    assert (await env.api.delete(f"/api/incident-reports/{rep['id']}")).status_code == 204
    assert (await env.api.get(f"/api/incident-reports/{rep['id']}")).status_code == 404
