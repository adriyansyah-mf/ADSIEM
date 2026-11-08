"""Alert auto-block: condition matrix (fakes, no DB), TI reputation in the aggregator, graph hook."""
import asyncio
import json as _json
from types import SimpleNamespace

import pytest

from worker import webblock_auto
from worker.case_grouping import parse_exclusions
from worker.ti.aggregator import EnrichmentAggregator
from worker.ti.config import TIConfig

ALERT = "11111111-1111-1111-1111-111111111111"


class Result:
    def __init__(self, rows):
        self.rows = rows

    def __iter__(self):
        return iter(self.rows)

    def first(self):
        return self.rows[0] if self.rows else None


class FakeDB:
    def __init__(self, policy, rules, writes):
        self.policy, self.rules, self.writes = policy, rules, writes

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def commit(self):
        pass

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        if "web_block_policies" in sql:
            return Result(self.policy)
        if "web_allowlist" in sql:
            return Result(self.rules)
        self.writes.append((sql, params))
        return Result([SimpleNamespace(domain=(params or {}).get("domain"))] if "web_block_entries" in sql else [])


def setup(monkeypatch, policy=None, rules=()):
    writes = []
    policy = [SimpleNamespace(group_id="g", enabled=True, alert_enabled=True, alert_block_days=7)] \
        if policy is None else policy
    monkeypatch.setattr(webblock_auto, "AsyncSessionLocal", lambda: FakeDB(policy, list(rules), writes))

    async def excl():
        return parse_exclusions("")
    monkeypatch.setattr(webblock_auto.alert_iocs, "_exclusions", excl)
    return writes


def rep(value, kind="domain", malicious=True):
    return SimpleNamespace(ioc_value=value, ioc_type=kind, malicious=malicious)


def enrich(*reps, domains=("c2.example.com",)):
    return SimpleNamespace(iocs=[{"type": "domain", "value": d} for d in domains], reputation=list(reps))


async def run(verdict="monitor", fields=None, enrichment=None, tags=("attack.command-and-control",),
              title="Beacon", group="g"):
    return await webblock_auto.maybe_block(ALERT, group, title, verdict, fields or {},
                                           enrichment or enrich(rep("c2.example.com")), tags=list(tags))


async def test_ti_malicious_outbound_blocks(monkeypatch):
    writes = setup(monkeypatch)
    assert await run() == ["c2.example.com"]
    inserts = [w for w in writes if "web_block_entries" in w[0]]
    assert inserts[0][1]["group"] == "g" and "threat intelligence" in inserts[0][1]["reason"]
    assert any("alert_notes" in w[0] for w in writes)
    assert any("pg_advisory_xact_lock" in w[0] for w in writes)


async def test_escalate_verdict_blocks_without_ti(monkeypatch):
    setup(monkeypatch)
    assert await run(verdict="escalate", fields={"url.domain": "c2.example.com"}, enrichment=enrich()) == ["c2.example.com"]


async def test_url_reputation_blocks_its_host(monkeypatch):
    setup(monkeypatch)
    e = enrich(rep("http://c2.example.com/a", "url"))
    assert await run(enrichment=e) == ["c2.example.com"]


@pytest.mark.parametrize("name,kwargs,policy", [
    ("policy disabled", {}, [SimpleNamespace(group_id="g", enabled=False, alert_enabled=True, alert_block_days=7)]),
    ("alert switch off", {}, [SimpleNamespace(group_id="g", enabled=True, alert_enabled=False, alert_block_days=7)]),
    ("no policy", {}, []),
    ("non-outbound family", {"tags": ["attack.persistence"], "title": "Run key"}, None),
    ("not malicious, monitor", {"enrichment": enrich(rep("c2.example.com", malicious=False))}, None),
    ("other domain malicious", {"enrichment": enrich(rep("other.example.org"))}, None),
    ("false positive verdict", {"verdict": "false_positive", "enrichment": enrich()}, None),
    ("web_block event", {"fields": {"event.action": "web_block"}}, None),
])
async def test_failing_condition_writes_nothing(monkeypatch, name, kwargs, policy):
    writes = setup(monkeypatch, policy=policy)
    assert await run(**kwargs) == []
    assert writes == [], name


async def test_default_policy_is_the_fallback(monkeypatch):
    setup(monkeypatch, policy=[SimpleNamespace(group_id="default", enabled=True, alert_enabled=True,
                                               alert_block_days=3)])
    assert await run() == ["c2.example.com"]


async def test_group_policy_beats_default(monkeypatch):
    setup(monkeypatch, policy=[
        SimpleNamespace(group_id="default", enabled=True, alert_enabled=True, alert_block_days=3),
        SimpleNamespace(group_id="g", enabled=True, alert_enabled=False, alert_block_days=3)])
    assert await run() == []


async def test_allowlisted_domain_is_skipped(monkeypatch):
    writes = setup(monkeypatch, rules=[SimpleNamespace(domain="example.com", include_subdomains=True)])
    assert await run() == []
    assert writes == []


async def test_failure_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(webblock_auto, "AsyncSessionLocal", boom)
    assert await run() == []


# --- aggregator reputation ---

class Fake:
    def __init__(self, data):
        self.data = data

    async def lookup_domain(self, v):
        return self.data

    lookup_url = lookup_domain


def vt(mal):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": 0}}}}


def aggregator(vt_data=None, uh_data=None):
    agg = EnrichmentAggregator(TIConfig())
    agg._vt, agg._otx = Fake(vt_data or {}), Fake({})
    agg._urlhaus, agg._whois = Fake(uh_data or {}), Fake({})
    return agg


async def test_reputation_urlhaus_listed_domain():
    out = await aggregator(uh_data={"query_status": "ok", "urlhaus_reference": "https://urlhaus.abuse.ch/x"}) \
        .enrich("contacted bad-host.com today")
    r = [x for x in out.reputation if x.ioc_value == "bad-host.com"]
    assert r and r[0].malicious and r[0].sources == ["urlhaus"] and r[0].ioc_type == "domain"
    assert out.provider_bullets and out.overall_risk > 0


async def test_reputation_virustotal_threshold():
    hi = await aggregator(vt_data=vt(5)).enrich("contacted bad-host.com today")
    lo = await aggregator(vt_data=vt(2)).enrich("contacted bad-host.com today")
    assert [(r.sources, r.malicious) for r in hi.reputation] == [(["virustotal"], True)]
    assert lo.reputation == []
    assert any("malicious=2" in b for b in lo.provider_bullets)


async def test_reputation_for_url():
    out = await aggregator(uh_data={"query_status": "ok", "urlhaus_status": "online"}) \
        .enrich("fetched http://bad-host.com/a.exe")
    assert any(r.ioc_type == "url" and r.malicious and "urlhaus" in r.sources for r in out.reputation)


# --- graph hook ---

async def test_persist_node_calls_web_auto_block(monkeypatch):
    from worker.graph import triage_graph
    calls = []

    class FakeLLM:
        def __init__(self, **kwargs):
            pass

        async def ainvoke(self, messages):
            return SimpleNamespace(content=_json.dumps({
                "verdict": "monitor", "confidence": 0.8, "triage_notes": "n", "mitre_techniques": [],
                "immediate_actions": [], "false_positive_reason": None, "threat_type": "c2",
                "search_queries": [],
            }))

    class Enrichment:
        provider_bullets, overall_risk, triage_hints, iocs, reputation = [], 0.0, [], [], []

    async def noop(*a, **k):
        return None

    async def empty(*a, **k):
        return []

    async def enr(text_blob, title):
        return Enrichment()

    async def get_setting(key, default=""):
        return default

    async def auto(*args):
        calls.append(args)

    monkeypatch.setattr(triage_graph, "NineRouterChatModel", FakeLLM)
    deps = {
        "enrich": enr, "escalate_severity": lambda base, risk: base, "suggest_mitre": lambda text: [],
        "retrieve_similar_cases": empty, "retrieve_sop_context": empty, "retrieve_feedback_context": empty,
        "enqueue_hunt": noop, "get_setting": get_setting, "set_alert_verdict": noop, "write_alert_note": noop,
        "tag_alert_with_mitre": noop, "run_soar_playbooks": noop, "update_alert_status": noop,
        "run_searches": noop, "web_auto_block": auto,
    }
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    state = {"alert_id": ALERT, "title": "Beacon", "severity": "medium", "source_ip": "45.33.32.156",
             "hostname": "h1", "decoded_fields": {"url.full": "http://x.example/a"}, "group_id": "blue"}
    await graph.ainvoke(state)
    await asyncio.sleep(0)
    assert len(calls) == 1
    assert calls[0][:4] == (ALERT, "blue", "Beacon", "monitor")
    assert calls[0][4] == state["decoded_fields"] and calls[0][6] == "c2"


# --- AI verdict alone blocks only event destination indicators ---

async def test_escalate_blocks_only_event_origin_domains(monkeypatch):
    writes = setup(monkeypatch)
    e = enrich(domains=("cdn.example.org",))
    got = await run(verdict="escalate", fields={"url.domain": "c2.example.com"}, enrichment=e)
    assert got == ["c2.example.com"]
    assert [w[1]["domain"] for w in writes if "web_block_entries" in w[0]] == ["c2.example.com"]


async def test_ti_malicious_text_origin_domain_blocks_under_monitor(monkeypatch):
    setup(monkeypatch)
    e = enrich(rep("cdn.example.org"), domains=("cdn.example.org",))
    assert await run(verdict="monitor", fields={"url.domain": "c2.example.com"}, enrichment=e) == ["cdn.example.org"]
