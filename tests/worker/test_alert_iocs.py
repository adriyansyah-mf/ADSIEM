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
    bodies = {}

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.content:
            bodies[request.url.path] = json.loads(request.content)
        return httpx.Response(404 if request.method == "HEAD" else 200, json={})

    _fake_es(monkeypatch, handler)
    await alert_iocs.ensure_index()
    assert calls == [("PUT", "/_index_template/alert_iocs"), ("HEAD", "/alert_iocs"), ("PUT", "/alert_iocs")]
    template = bodies["/_index_template/alert_iocs"]
    assert template["index_patterns"] == ["alert_iocs"]
    assert template["template"]["mappings"] == alert_iocs.MAPPING["mappings"]


async def test_delete_for_alerts_batches_by_1000(es):
    await alert_iocs.delete_for_alerts([f"id{i}" for i in range(1500)])
    deletes = [json.loads(body) for _, path, body in es if path == "/alert_iocs/_delete_by_query"]
    assert [len(d["query"]["terms"]["alert_id"]) for d in deletes] == [1000, 500]


async def test_elasticsearch_errors_are_logged_not_raised(monkeypatch):
    _fake_es(monkeypatch, lambda request: httpx.Response(500, text="boom"))
    await alert_iocs.index_docs(alert_iocs.collect(META, "45.33.32.156", {}, [], EXCL))
    await alert_iocs.delete_for_alerts(["a1"])
    await alert_iocs.ensure_index()


import asyncio
import json as _json
from types import SimpleNamespace
from uuid import UUID


@pytest.fixture
def captured(monkeypatch):
    docs = []

    async def index_docs(batch):
        docs.extend(batch)
        return 0

    async def get_setting(key, default=""):
        return "151.101.0.0/16" if key == "case_ioc_exclusions" else default

    from worker import settings_cache
    monkeypatch.setattr(alert_iocs, "index_docs", index_docs)
    monkeypatch.setattr(settings_cache, "get_setting", get_setting)
    return docs


async def test_new_alert_indexes_alert_and_event_indicators(captured):
    await alert_iocs.index_new_alert(META, "45.33.32.156", {"destination.ip": "151.101.1.69", "url.full": "http://x.example/a"})
    assert pairs(captured) == {("ip", "45.33.32.156", "alert"), ("url", "http://x.example/a", "event")}


async def test_triaged_alert_is_rewritten_with_ti_indicators_and_verdict(captured, monkeypatch):
    alert_id = "11111111-1111-1111-1111-111111111111"
    row = SimpleNamespace(id=UUID(alert_id), group_id="blue", severity="critical", hostname="h1", agent_id=None,
                          title="Beacon", created_at=datetime(2026, 11, 7, tzinfo=timezone.utc),
                          source_ip="45.33.32.156", ai_verdict=None)

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, model, key):
            return row if key == UUID(alert_id) else None

    from worker import database
    monkeypatch.setattr(database, "AsyncSessionLocal", Session)
    await alert_iocs.index_triaged_alert(alert_id, {}, [{"type": "domain", "value": "c2.example"}], "escalate")
    assert pairs(captured) == {("ip", "45.33.32.156", "alert"), ("domain", "c2.example", "ti")}
    assert {d["ai_verdict"] for _, d in captured} == {"escalate"}
    assert {d["severity_rank"] for _, d in captured} == {4}


async def test_triaged_unknown_alert_indexes_nothing(captured, monkeypatch):
    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, model, key):
            return None

    from worker import database
    monkeypatch.setattr(database, "AsyncSessionLocal", Session)
    await alert_iocs.index_triaged_alert("11111111-1111-1111-1111-111111111111", {}, [], "monitor")
    assert captured == []


async def test_persist_node_hands_triage_result_to_index_dependency(monkeypatch):
    from worker.graph import triage_graph
    calls = []

    class FakeLLM:
        def __init__(self, **kwargs):
            pass

        async def ainvoke(self, messages):
            return SimpleNamespace(content=_json.dumps({
                "verdict": "monitor", "confidence": 0.8, "triage_notes": "n", "mitre_techniques": [],
                "immediate_actions": [], "false_positive_reason": None, "threat_type": "other",
                "search_queries": [],
            }))

    class Enrichment:
        provider_bullets, overall_risk, triage_hints = [], 0.0, []
        iocs = [{"type": "domain", "value": "c2.example"}]

    async def noop(*a, **k):
        return None

    async def empty(*a, **k):
        return []

    async def enrich(text_blob, title):
        return Enrichment()

    async def get_setting(key, default=""):
        return default

    async def index_alert_iocs(alert_id, fields, extracted, verdict):
        calls.append((alert_id, fields, extracted, verdict))

    monkeypatch.setattr(triage_graph, "NineRouterChatModel", FakeLLM)
    deps = {
        "enrich": enrich, "escalate_severity": lambda base, risk: base, "suggest_mitre": lambda text: [],
        "retrieve_similar_cases": empty, "retrieve_sop_context": empty, "retrieve_feedback_context": empty,
        "enqueue_hunt": noop, "get_setting": get_setting, "set_alert_verdict": noop, "write_alert_note": noop,
        "tag_alert_with_mitre": noop, "run_soar_playbooks": noop, "update_alert_status": noop,
        "run_searches": noop, "index_alert_iocs": index_alert_iocs,
    }
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    state = {"alert_id": "11111111-1111-1111-1111-111111111111", "title": "Beacon", "severity": "medium",
             "source_ip": "45.33.32.156", "hostname": "h1", "decoded_fields": {"url.full": "http://x.example/a"},
             "group_id": "blue"}
    await graph.ainvoke(state)
    await asyncio.sleep(0)
    assert calls == [(state["alert_id"], state["decoded_fields"], Enrichment.iocs, "monitor")]


def test_case_indicators_become_extracted_items():
    assert alert_iocs.indicators_to_extracted(
        ["ip:45.33.32.156", "ip:2001:db8::1", "domain:c2.example", "url:http://x.example/a",
         "hash:" + "a" * 64, "hash:" + "b" * 40, "hash:" + "c" * 32, "hash:zz", "account:admin"]
    ) == [{"type": "ipv4", "value": "45.33.32.156"}, {"type": "ipv4", "value": "2001:db8::1"},
          {"type": "domain", "value": "c2.example"}, {"type": "url", "value": "http://x.example/a"},
          {"type": "hash_sha256", "value": "a" * 64}, {"type": "hash_sha1", "value": "b" * 40},
          {"type": "hash_md5", "value": "c" * 32}]


async def test_retention_deletes_indicator_docs_of_purged_alerts(monkeypatch):
    from worker import maintenance
    ids = [UUID(int=1), UUID(int=2)]
    deleted = []

    class Result:
        def scalars(self):
            return SimpleNamespace(all=lambda: ids)

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def execute(self, statement):
            return Result()

        async def commit(self):
            pass

    async def delete_for_alerts(alert_ids):
        deleted.extend(alert_ids)

    monkeypatch.setattr(maintenance, "AsyncSessionLocal", Session)
    monkeypatch.setattr(alert_iocs, "delete_for_alerts", delete_for_alerts)
    assert await maintenance._purge_alerts(180) == 2
    assert deleted == [str(i) for i in ids]
    assert await maintenance._purge_alerts(0) == 0


async def test_index_docs_returns_zero_on_success(es):
    assert await alert_iocs.index_docs(alert_iocs.collect(META, "45.33.32.156", {}, [], EXCL)) == 0
    assert await alert_iocs.index_docs([]) == 0


async def test_index_docs_returns_all_failed_on_http_error(monkeypatch):
    _fake_es(monkeypatch, lambda request: httpx.Response(500, text="boom"))
    docs = alert_iocs.collect(META, "45.33.32.156", {}, [{"type": "domain", "value": "c2.example"}], EXCL)
    assert len(docs) == 2
    assert await alert_iocs.index_docs(docs) == 2


async def test_index_docs_counts_failed_items(monkeypatch):
    items = [{"index": {"status": 201}}, {"index": {"status": 400, "error": {"type": "bad"}}}]
    _fake_es(monkeypatch, lambda request: httpx.Response(200, json={"errors": True, "items": items}))
    docs = alert_iocs.collect(META, "45.33.32.156", {}, [{"type": "domain", "value": "c2.example"}], EXCL)
    assert await alert_iocs.index_docs(docs) == 1


def test_domain_fields_never_record_ip_addresses():
    fields = {"url.domain": "10.0.0.5", "dns.question.name": "45.33.32.156"}
    assert alert_iocs.collect(META, None, fields, None, EXCL) == []


def test_url_host_must_pass_ip_exclusions():
    assert alert_iocs.collect(META, None, {"url.full": "http://192.168.1.10/a"}, None, EXCL) == []
    docs = alert_iocs.collect(META, None, {"url.full": "http://45.33.32.156/a"}, None, EXCL)
    assert pairs(docs) == {("url", "http://45.33.32.156/a", "event")}


@pytest.mark.parametrize("url", ["http://user@evil.com/x", "http://evil.com:8080/x"])
def test_url_with_userinfo_or_port_honours_owned_domains(url):
    assert alert_iocs.collect(META, None, {"url.full": url}, None, parse_exclusions("evil.com")) == []


def test_email_in_owned_domain_is_dropped():
    fields = {"user.email": "bob@corp.example"}
    assert alert_iocs.collect(META, None, fields, None, parse_exclusions("corp.example")) == []
    assert pairs(alert_iocs.collect(META, None, fields, None, parse_exclusions(""))) == {
        ("email", "bob@corp.example", "event")}


def test_unicode_url_host_is_punycoded():
    docs = alert_iocs.collect(META, None, {"url.full": "http://Bücher.example/A"}, None, EXCL)
    assert pairs(docs) == {("url", "http://xn--bcher-kva.example/a", "event")}


def test_sysmon_imphash_is_not_a_file_hash():
    fields = {"Hashes": "MD5=" + "a" * 32 + ",SHA256=" + "b" * 64 + ",IMPHASH=" + "c" * 32}
    assert pairs(alert_iocs.collect(META, None, fields, None, EXCL)) == {
        ("md5", "a" * 32, "event"), ("sha256", "b" * 64, "event")}


def test_overlong_values_are_dropped():
    assert alert_iocs.collect(META, None, {"url.full": "http://45.33.32.156/" + "a" * 3000}, None, EXCL) == []
