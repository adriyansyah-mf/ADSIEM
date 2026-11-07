# tests/worker/test_alert_iocs.py
"""Attacker indicators per alert (worker/alert_iocs.py): extraction rules and
the Elasticsearch writes, with Elasticsearch faked by httpx.MockTransport."""
import json
from datetime import datetime, timezone

import httpx
import pytest

from worker import alert_iocs, es_client
from worker.case_grouping import parse_exclusions

META = alert_iocs.AlertMeta(alert_id="a1", group_id="blue", severity="high", hostname="h1", agent_id="ag1",
                            rule_title="Beacon", created_at=datetime(2026, 11, 7, tzinfo=timezone.utc))
EXCL = parse_exclusions("")


def pairs(docs):
    return {(d["type"], d["value"], d["origin"]) for _, d in docs}


def test_collects_every_origin_and_type():
    fields = {"destination.ip": "151.101.1.69", "dns.question.name": "Evil.Example.",
              "url.full": "HTTP://Evil.Example/x", "Hashes": "SHA256=" + "A" * 64 + ",MD5=" + "b" * 32,
              "user.email": "Bob@Corp.example"}
    extracted = [{"type": "domain", "value": "c2.example"}, {"type": "hash_sha1", "value": "C" * 40},
                 {"type": "command", "value": "whoami"}]
    docs = alert_iocs.collect(META, "45.33.32.156", fields, extracted, EXCL)
    assert pairs(docs) == {
        ("ip", "45.33.32.156", "alert"), ("ip", "151.101.1.69", "event"), ("domain", "evil.example", "event"),
        ("url", "http://evil.example/x", "event"), ("sha256", "a" * 64, "event"), ("md5", "b" * 32, "event"),
        ("email", "bob@corp.example", "event"), ("domain", "c2.example", "ti"), ("sha1", "c" * 40, "ti"),
    }


def test_drops_private_and_excluded_indicators():
    fields = {"destination.ip": "10.0.0.5", "dns.question.name": "update.microsoft.com",
              "url.full": "https://github.com/a/b"}
    assert alert_iocs.collect(META, "192.168.1.9", fields, [{"type": "ipv4", "value": "8.8.8.8"}], EXCL) == []


def test_idn_domains_become_punycode():
    docs = alert_iocs.collect(META, None, {"dns.question.name": "bücher.example"}, [], EXCL)
    assert pairs(docs) == {("domain", "xn--bcher-kva.example", "event")}


def test_extracted_origin_can_be_overridden():
    docs = alert_iocs.collect(META, None, {}, [{"type": "url", "value": "http://x.example/p"}], EXCL,
                              extracted_origin="alert")
    assert pairs(docs) == {("url", "http://x.example/p", "alert")}


def test_doc_shape_and_stable_id():
    [(doc_id, doc)] = alert_iocs.collect(META, "45.33.32.156", {}, [], EXCL)
    assert doc_id == alert_iocs.doc_id("a1", "ip", "45.33.32.156")
    assert doc == {"alert_id": "a1", "group_id": "blue", "type": "ip", "value": "45.33.32.156",
                   "ioc_key": "ip:45.33.32.156", "severity": "high", "severity_rank": 3, "hostname": "h1",
                   "agent_id": "ag1", "rule_title": "Beacon", "ai_verdict": None, "origin": "alert",
                   "created_at": "2026-11-07T00:00:00+00:00"}
    assert alert_iocs.collect(META, "45.33.32.156", {}, [], EXCL)[0][0] == doc_id


def _fake_es(monkeypatch, handler):
    monkeypatch.setattr(es_client, "_client",
                        httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://es"))


@pytest.fixture
def es(monkeypatch):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.content.decode()))
        if request.url.path == "/_bulk":
            return httpx.Response(200, json={"errors": False, "items": []})
        return httpx.Response(200, json={})

    _fake_es(monkeypatch, handler)
    return calls


async def test_index_docs_bulk_targets_alert_iocs(es):
    docs = alert_iocs.collect(META, "45.33.32.156", {}, [], EXCL)
    await alert_iocs.index_docs(docs)
    method, path, body = es[0]
    lines = [json.loads(line) for line in body.strip().split("\n")]
    assert (method, path) == ("POST", "/_bulk")
    assert lines[0] == {"index": {"_index": "alert_iocs", "_id": docs[0][0]}}
    assert lines[1]["value"] == "45.33.32.156"


async def test_index_docs_skips_empty(es):
    await alert_iocs.index_docs([])
    assert es == []


async def test_ensure_index_creates_mapping_once(monkeypatch):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(404 if request.method == "HEAD" else 200, json={})

    _fake_es(monkeypatch, handler)
    await alert_iocs.ensure_index()
    assert calls == [("HEAD", "/alert_iocs"), ("PUT", "/alert_iocs")]


async def test_delete_for_alerts_batches_by_1000(es):
    await alert_iocs.delete_for_alerts([f"id{i}" for i in range(1500)])
    deletes = [json.loads(body) for _, path, body in es if path == "/alert_iocs/_delete_by_query"]
    assert [len(d["query"]["terms"]["alert_id"]) for d in deletes] == [1000, 500]


async def test_elasticsearch_errors_are_logged_not_raised(monkeypatch):
    _fake_es(monkeypatch, lambda request: httpx.Response(500, text="boom"))
    await alert_iocs.index_docs(alert_iocs.collect(META, "45.33.32.156", {}, [], EXCL))
    await alert_iocs.delete_for_alerts(["a1"])
    await alert_iocs.ensure_index()
