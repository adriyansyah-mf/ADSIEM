# tests/server-api/test_ai_endpoint_tools.int.py
"""The AI tools for endpoint detections (assistant_tools, also used by AI
investigations): process_tree for an alert and known_malware_lookup against
the platform's own hash set, both group-scoped and read-only."""
import asyncio
from uuid import uuid4

import pytest

from app.models.models import Alert
from app.services import assistant_tools, investigation_ledger, investigator
from worker import malware_hashes as mh


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


def test_tools_are_read_only_tier0():
    names = {t["name"] for t in assistant_tools.TOOLS}
    for tool in ("process_tree", "known_malware_lookup"):
        assert tool in names and tool in investigator.READ_ONLY_TOOLS
        assert investigation_ledger.tool_tier(tool) == 0


async def test_known_malware_lookup(evidence_api):
    known, allowed, unknown = "ab" * 32, "cd" * 32, "ef" * 32
    async with evidence_api.sessions() as db:
        await mh.upsert(db, [{"sha256": known, "label": "AgentTesla"}, {"sha256": allowed}], "malwarebazaar")
        await mh.set_status(db, allowed, "allowed")
    async with evidence_api.sessions() as db:
        out = await assistant_tools.run_tool("known_malware_lookup",
                                             {"hashes": f"{known.upper()}, {allowed};{unknown}, junk"}, db, "blue")
    by = {r["sha256"]: r for r in out["results"]}
    assert by[known]["known"] and by[known]["label"] == "AgentTesla" and by[known]["source"] == "malwarebazaar"
    assert by[allowed]["known"] is False and by[allowed]["status"] == "allowed"
    assert by[unknown] == {"sha256": unknown, "known": False}
    async with evidence_api.sessions() as db:
        assert "error" in await assistant_tools.run_tool("known_malware_lookup", {"hashes": "nope"}, db, None)


async def test_process_tree_tool(evidence_api, monkeypatch):
    from app.core import es_client

    agent = str(evidence_api.agents["blue"])
    event = {"id": "ev1", "agent_id": agent, "created_at": "2026-11-02T10:00:00+00:00",
             "log_type": "linux_network_connect", "decoded_fields": {"process.pid": "1100"}}
    start = {"id": "x1", "agent_id": agent, "log_type": "linux_process_exec", "created_at": "2026-11-02T09:59:50+00:00",
             "decoded_fields": {"ProcessId": "1100", "ParentProcessId": "0", "Image": "/usr/bin/curl",
                                "CommandLine": "curl -s " + "A" * 1000}}

    async def get_log(doc_id):
        return event

    async def search(query, size=25, sort=None, search_after=None):
        return ([start] if "ProcessId" in str(query) and "linux_process_exec" in str(query) else []), 0, None

    monkeypatch.setattr(es_client, "get_log", get_log)
    monkeypatch.setattr(es_client, "search", search)
    ids = {}
    async with evidence_api.sessions() as db:
        for group in ("blue", "red"):
            a = Alert(title="t", severity="high", agent_id=evidence_api.agents[group], group_id=group,
                      hostname=f"{group}-host", event_id=uuid4())
            db.add(a)
            await db.commit()
            ids[group] = str(a.id)

    async with evidence_api.sessions() as db:
        out = await assistant_tools.run_tool("process_tree", {"alert_id": ids["blue"]}, db, "blue")
        assert out["hostname"] == "blue-host"
        node = out["nodes"][0]
        assert node["alert_process"] and node["image"] == "/usr/bin/curl" and len(node["command_line"]) == 300
        assert await assistant_tools.run_tool("process_tree", {"alert_id": ids["red"]}, db, "blue") == {"error": "not found"}
        assert await assistant_tools.run_tool("process_tree", {"alert_id": "x"}, db, None) == {"error": "invalid alert_id"}
