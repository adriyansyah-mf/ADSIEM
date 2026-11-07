# Threat IoCs (Stage A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record every attacker indicator (IP, domain, URL, hash, email) of every alert in Elasticsearch and show them in a new "Threat IoCs" dashboard page with counts, hosts, first/last seen and linked alerts.

**Architecture:** The worker writes one document per (alert, indicator) into a new Elasticsearch index `alert_iocs` when an alert is created, and rewrites them after AI triage (adding TI-extracted indicators and the AI verdict). Retention deletes them with their alerts; a one-shot job backfills old alerts. The API aggregates the index per indicator, always filtered by the caller's group, and loads drill-down alerts from Postgres. A React page lists them per type.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async, httpx (Elasticsearch REST), pytest + pytest-asyncio, React 18 + TypeScript + TanStack Query + Tailwind.

**Spec:** `docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md` (section A)

## Global Constraints

- Group scoping is mandatory: every API query filters `group_id` from `get_scoped_group()` (None = superadmin, no filter).
- Read permission for every IoC route: `alerts:read`.
- Elasticsearch failures never fail alert creation or triage: log and continue.
- No new Python or npm dependencies.
- Indicator types are exactly: `ip`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`.
- Severity rank: `info`=0, `low`=1, `medium`=2, `high`=3, `critical`=4.
- Exclusions reuse `case_grouping.parse_exclusions(get_setting("case_ioc_exclusions", ""))`; non-global IPs are dropped.
- CI pins `pytest==8.3.4` and `pytest-asyncio==0.24.0`; before pushing, run the suites in a venv with those versions (see "Test commands").
- Worker and server-api tests run in separate pytest processes (shared Prometheus metric names).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Test commands

```bash
# disposable Postgres (only needed for *.int.py tests)
docker run -d --rm --name adsiem-testpg -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc -e POSTGRES_DB=test -p 55432:5432 pgvector/pgvector:pg16
export JWT_SECRET=ci-test-secret-0123456789abcdef0123456789abcdef
export TEST_DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55432/test DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55432/test
# CI-equivalent pytest
python3 -m venv --system-site-packages /tmp/adsiem-ci-venv && /tmp/adsiem-ci-venv/bin/pip install -q pytest==8.3.4 pytest-asyncio==0.24.0
PY=/tmp/adsiem-ci-venv/bin/python
```

## File Structure

| File | Responsibility |
|---|---|
| `worker/worker/alert_iocs.py` (create) | Indicator extraction (`collect`), index mapping, ES writes/deletes, write entry points for alert creation/triage, backfill |
| `worker/worker/alert_manager.py` (modify) | Index indicators of each new alert |
| `worker/worker/graph/triage_graph.py` (modify) | `persist_node` re-indexes with TI indicators + verdict |
| `worker/worker/ai_analyst.py` (modify) | Wire the `index_alert_iocs` dependency |
| `worker/worker/maintenance.py` (modify) | Delete indicator docs of purged alerts |
| `worker/worker/main.py` (modify) | Create index at start; run backfill once |
| `server-api/app/core/es_client.py` (modify) | `search_iocs()` against `alert_iocs` |
| `server-api/app/api/routes/iocs.py` (create) | `GET /api/iocs`, `GET /api/iocs/alerts` |
| `server-api/app/main.py` (modify) | Register the router |
| `dashboard/src/hooks/useIocs.ts` (create) | Query hooks and types |
| `dashboard/src/pages/ThreatIocsPage.tsx` (create) | The page |
| `dashboard/src/App.tsx`, `dashboard/src/components/AppSidebar.tsx` (modify) | Route + menu entry |
| `tests/worker/test_alert_iocs.py` (create) | Extraction, ES writes, triage hook, retention |
| `tests/worker/test_alert_iocs_backfill.int.py` (create) | Backfill against Postgres |
| `tests/server-api/test_iocs_api.int.py` (create) | API scoping, parsing, drill-down |

---

### Task 1: Indicator extraction and Elasticsearch writes

**Files:**
- Create: `worker/worker/alert_iocs.py`
- Test: `tests/worker/test_alert_iocs.py`

**Interfaces:**
- Consumes: `worker.case_grouping` (`_DEST_IP_FIELDS`, `_DOMAIN_FIELDS`, `_URL_FIELDS`, `_HASH_FIELDS`, `_HASH_RE`, `parse_exclusions`), `worker.es_client._get_client()`.
- Produces:
  - `INDEX = "alert_iocs"`, `MAPPING: dict`
  - `@dataclass(frozen=True) AlertMeta(alert_id: str, group_id: str, severity: str, hostname: str | None, agent_id: str | None, rule_title: str, created_at: datetime, ai_verdict: str | None = None)`
  - `doc_id(alert_id: str, ioc_type: str, value: str) -> str`
  - `collect(meta: AlertMeta, source_ip: str | None, fields: dict | None, extracted: list | None, exclusions: tuple[list, set[str]], *, extracted_origin: str = "ti") -> list[tuple[str, dict]]`
  - `async ensure_index() -> None`, `async index_docs(docs: list[tuple[str, dict]]) -> None`, `async delete_for_alerts(alert_ids: list[str]) -> None`

- [ ] **Step 1: Write the failing tests**

`tests/worker/test_alert_iocs.py`:

```python
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
    fields = {"destination.ip": "203.0.113.7", "dns.question.name": "Evil.Example.",
              "url.full": "HTTP://Evil.Example/x", "Hashes": "SHA256=" + "A" * 64 + ",MD5=" + "b" * 32,
              "user.email": "Bob@Corp.example"}
    extracted = [{"type": "domain", "value": "c2.example"}, {"type": "hash_sha1", "value": "C" * 40},
                 {"type": "command", "value": "whoami"}]
    docs = alert_iocs.collect(META, "198.51.100.4", fields, extracted, EXCL)
    assert pairs(docs) == {
        ("ip", "198.51.100.4", "alert"), ("ip", "203.0.113.7", "event"), ("domain", "evil.example", "event"),
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
    [(doc_id, doc)] = alert_iocs.collect(META, "198.51.100.4", {}, [], EXCL)
    assert doc_id == alert_iocs.doc_id("a1", "ip", "198.51.100.4")
    assert doc == {"alert_id": "a1", "group_id": "blue", "type": "ip", "value": "198.51.100.4",
                   "ioc_key": "ip:198.51.100.4", "severity": "high", "severity_rank": 3, "hostname": "h1",
                   "agent_id": "ag1", "rule_title": "Beacon", "ai_verdict": None, "origin": "alert",
                   "created_at": "2026-11-07T00:00:00+00:00"}
    assert alert_iocs.collect(META, "198.51.100.4", {}, [], EXCL)[0][0] == doc_id


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
    docs = alert_iocs.collect(META, "198.51.100.4", {}, [], EXCL)
    await alert_iocs.index_docs(docs)
    method, path, body = es[0]
    lines = [json.loads(line) for line in body.strip().split("\n")]
    assert (method, path) == ("POST", "/_bulk")
    assert lines[0] == {"index": {"_index": "alert_iocs", "_id": docs[0][0]}}
    assert lines[1]["value"] == "198.51.100.4"


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
    await alert_iocs.index_docs(alert_iocs.collect(META, "198.51.100.4", {}, [], EXCL))
    await alert_iocs.delete_for_alerts(["a1"])
    await alert_iocs.ensure_index()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/worker/test_alert_iocs.py -q`
Expected: FAIL / ERROR with `ImportError: cannot import name 'alert_iocs' from 'worker'`.

- [ ] **Step 3: Write the implementation**

`worker/worker/alert_iocs.py`:

```python
# worker/worker/alert_iocs.py
"""Attacker indicators per alert, in the Elasticsearch index `alert_iocs`.

One document per (alert, indicator), id = sha1(alert_id|type|value), so writing
an alert again (after AI triage, or a backfill) overwrites instead of
duplicating. Unlike case_grouping.ioc_keys, domains and URLs are kept for every
alert family: this is an inventory, not a campaign key. Elasticsearch failures
are logged and never raised — alert creation and triage must not depend on it."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime

import structlog

from worker import es_client
from worker.case_grouping import (
    _DEST_IP_FIELDS, _DOMAIN_FIELDS, _HASH_FIELDS, _HASH_RE, _URL_FIELDS, parse_exclusions,
)

log = structlog.get_logger()

INDEX = "alert_iocs"
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_EMAIL_FIELDS = ("user.email", "email.from.address", "email.to.address", "SenderAddress", "RecipientAddress")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://([^/:?#]+)")
_HASH_TYPES = {64: "sha256", 40: "sha1", 32: "md5"}
_TI_TYPES = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
             "hash_md5": "md5", "hash_sha1": "sha1", "hash_sha256": "sha256"}
_DELETE_BATCH = 1000

_KEYWORD = {"type": "keyword"}
MAPPING = {"mappings": {"properties": {
    "alert_id": _KEYWORD, "group_id": _KEYWORD, "type": _KEYWORD, "value": _KEYWORD, "ioc_key": _KEYWORD,
    "severity": _KEYWORD, "severity_rank": {"type": "byte"}, "hostname": _KEYWORD, "agent_id": _KEYWORD,
    "rule_title": _KEYWORD, "ai_verdict": _KEYWORD, "origin": _KEYWORD, "created_at": {"type": "date"},
}}}


@dataclass(frozen=True)
class AlertMeta:
    alert_id: str
    group_id: str
    severity: str
    hostname: str | None
    agent_id: str | None
    rule_title: str
    created_at: datetime
    ai_verdict: str | None = None


def doc_id(alert_id: str, ioc_type: str, value: str) -> str:
    return hashlib.sha1(f"{alert_id}|{ioc_type}|{value}".encode()).hexdigest()


def _excluded_host(host: str, domains: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _ip(value, nets) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if not ip.is_global or any(ip in n for n in nets):
        return None
    return str(ip)


def _domain(value, domains) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    if not d or "." not in d or _ip(d, []) or _excluded_host(d, domains):
        return None
    try:
        return d.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _url(value, domains) -> str | None:
    u = str(value or "").strip()
    m = _URL_RE.match(u)
    if not m or _excluded_host(m.group(1).lower(), domains):
        return None
    return u.lower()


def _email(value) -> str | None:
    e = str(value or "").strip().lower()
    return e if _EMAIL_RE.match(e) else None


def _extracted(item) -> tuple[str | None, str | None]:
    if isinstance(item, dict):
        kind, value = item.get("type"), item.get("value")
    else:
        kind = getattr(getattr(item, "type", None), "value", None) or getattr(item, "type", None)
        value = getattr(item, "value", None)
    return (str(kind) if kind else None), (str(value) if value else None)


def collect(meta: AlertMeta, source_ip: str | None, fields: dict | None, extracted: list | None,
            exclusions: tuple[list, set[str]], *, extracted_origin: str = "ti") -> list[tuple[str, dict]]:
    """(doc_id, document) for every indicator of one alert, first origin wins."""
    nets, domains = exclusions
    fields = fields or {}
    found: dict[tuple[str, str], str] = {}

    def add(kind: str, value: str | None, origin: str) -> None:
        if value and (kind, value) not in found:
            found[(kind, value)] = origin

    add("ip", _ip(source_ip, nets), "alert")
    for name in _DEST_IP_FIELDS:
        add("ip", _ip(fields.get(name), nets), "event")
    for name in _DOMAIN_FIELDS:
        add("domain", _domain(fields.get(name), domains), "event")
    for name in _URL_FIELDS:
        add("url", _url(fields.get(name), domains), "event")
    for name in (*_HASH_FIELDS, "Hashes"):
        for h in _HASH_RE.findall(str(fields.get(name) or "")):
            add(_HASH_TYPES[len(h)], h.lower(), "event")
    for name in _EMAIL_FIELDS:
        add("email", _email(fields.get(name)), "event")

    for item in extracted or []:
        kind, value = _extracted(item)
        mapped = _TI_TYPES.get(kind or "")
        if mapped == "ip":
            add("ip", _ip(value, nets), extracted_origin)
        elif mapped == "domain":
            add("domain", _domain(value, domains), extracted_origin)
        elif mapped == "url":
            add("url", _url(value, domains), extracted_origin)
        elif mapped and value and len(value) == {"sha256": 64, "sha1": 40, "md5": 32}[mapped]:
            add(mapped, value.lower(), extracted_origin)

    return [(doc_id(meta.alert_id, kind, value), {
        "alert_id": meta.alert_id, "group_id": meta.group_id, "type": kind, "value": value,
        "ioc_key": f"{kind}:{value}", "severity": meta.severity,
        "severity_rank": SEVERITY_RANK.get(meta.severity, 0), "hostname": meta.hostname,
        "agent_id": meta.agent_id, "rule_title": meta.rule_title, "ai_verdict": meta.ai_verdict,
        "origin": origin, "created_at": meta.created_at.isoformat(),
    }) for (kind, value), origin in found.items()]


async def ensure_index() -> None:
    """Idempotent: create `alert_iocs` with its mapping when missing."""
    client = es_client._get_client()
    try:
        if (await client.head(f"/{INDEX}")).status_code == 200:
            return
        resp = await client.put(f"/{INDEX}", json=MAPPING)
        if resp.status_code not in (200, 201) and "resource_already_exists_exception" not in resp.text:
            log.error("alert_iocs_index_create_failed", status=resp.status_code, body=resp.text[:500])
    except Exception as exc:  # Elasticsearch down at start: the next start retries
        log.error("alert_iocs_index_create_failed", error=str(exc))


async def index_docs(docs: list[tuple[str, dict]]) -> None:
    if not docs:
        return
    lines = []
    for _id, doc in docs:
        lines.append(json.dumps({"index": {"_index": INDEX, "_id": _id}}))
        lines.append(json.dumps(doc, default=str))
    try:
        resp = await es_client._get_client().post(
            "/_bulk", content="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("errors"):
            failed = [i["index"]["error"] for i in result.get("items", []) if i.get("index", {}).get("error")]
            log.warning("alert_iocs_index_partial", failed=len(failed), first=str(failed[:1])[:300])
    except Exception as exc:
        log.warning("alert_iocs_index_failed", docs=len(docs), error=str(exc))


async def delete_for_alerts(alert_ids: list[str]) -> None:
    client = es_client._get_client()
    for start in range(0, len(alert_ids), _DELETE_BATCH):
        batch = alert_ids[start:start + _DELETE_BATCH]
        try:
            resp = await client.post(f"/{INDEX}/_delete_by_query", params={"conflicts": "proceed"},
                                     json={"query": {"terms": {"alert_id": batch}}}, timeout=60)
            if resp.status_code != 404:
                resp.raise_for_status()
        except Exception as exc:
            log.warning("alert_iocs_delete_failed", alerts=len(batch), error=str(exc))
```

Note: `parse_exclusions` is imported here because Task 2 adds `_exclusions()` to this module.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/worker/test_alert_iocs.py -q`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add worker/worker/alert_iocs.py tests/worker/test_alert_iocs.py
git commit -m "feat(iocs): extract alert indicators and write them to alert_iocs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Index indicators at alert creation and after triage

**Files:**
- Modify: `worker/worker/alert_iocs.py` (append)
- Modify: `worker/worker/alert_manager.py:171-202` (inside `create_alert`)
- Modify: `worker/worker/graph/triage_graph.py:255-277` (`persist_node`)
- Modify: `worker/worker/ai_analyst.py:847-879` (deps dict)
- Modify: `worker/worker/main.py:33,151` (ensure index)
- Modify: `docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md` (section A "Writing")
- Test: `tests/worker/test_alert_iocs.py` (append)

**Interfaces:**
- Consumes: Task 1 `AlertMeta`, `collect`, `index_docs`, `ensure_index`.
- Produces:
  - `async index_new_alert(meta: AlertMeta, source_ip: str | None, fields: dict | None) -> None`
  - `async index_triaged_alert(alert_id: str, fields: dict | None, extracted: list | None, verdict: str) -> None`
  - `meta_of(alert, verdict: str | None = None) -> AlertMeta` (used by Task 3 backfill)
  - triage dependency key `"index_alert_iocs"` with the `index_triaged_alert` signature.

- [ ] **Step 1: Write the failing tests** (append to `tests/worker/test_alert_iocs.py`)

```python
import asyncio
import json as _json
from types import SimpleNamespace
from uuid import UUID


@pytest.fixture
def captured(monkeypatch):
    docs = []

    async def index_docs(batch):
        docs.extend(batch)

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/worker/test_alert_iocs.py -q`
Expected: the 4 new tests FAIL (`AttributeError: module 'worker.alert_iocs' has no attribute 'index_new_alert'`, and `calls == []` for the graph test).

If the graph test fails on a missing dependency key other than `index_alert_iocs` (the `monitor` path may read more deps on this branch), add that key to `deps` as `noop`, and re-run until the only failure is the empty `calls`.

- [ ] **Step 3: Write the implementation**

Append to `worker/worker/alert_iocs.py`:

```python
async def _exclusions() -> tuple[list, set[str]]:
    from worker import settings_cache
    return parse_exclusions(await settings_cache.get_setting("case_ioc_exclusions", ""))


def meta_of(alert, verdict: str | None = None) -> AlertMeta:
    """AlertMeta from an Alert row (worker.models.Alert or anything shaped like it)."""
    return AlertMeta(alert_id=str(alert.id), group_id=alert.group_id, severity=alert.severity,
                     hostname=alert.hostname, agent_id=str(alert.agent_id) if alert.agent_id else None,
                     rule_title=alert.title, created_at=alert.created_at,
                     ai_verdict=verdict if verdict is not None else alert.ai_verdict)


async def index_new_alert(meta: AlertMeta, source_ip: str | None, fields: dict | None) -> None:
    """Every alert, whether or not AI triage runs for it (ai_min_severity gates triage)."""
    try:
        docs = collect(meta, source_ip, fields, None, await _exclusions())
    except Exception:
        log.exception("alert_iocs_collect_failed", alert_id=meta.alert_id)
        return
    await index_docs(docs)


async def index_triaged_alert(alert_id: str, fields: dict | None, extracted: list | None, verdict: str) -> None:
    """Rewrite the alert's documents with TI-extracted indicators and the AI verdict."""
    import uuid
    from worker import database
    from worker.models import Alert
    try:
        async with database.AsyncSessionLocal() as db:
            alert = await db.get(Alert, uuid.UUID(str(alert_id)))
        if alert is None:
            return
        docs = collect(meta_of(alert, verdict), alert.source_ip, fields, extracted, await _exclusions())
    except Exception:
        log.exception("alert_iocs_collect_failed", alert_id=str(alert_id))
        return
    await index_docs(docs)
```

In `worker/worker/alert_manager.py`, inside `create_alert`, capture the creation time right after `alert_id: uuid.UUID = alert.id` (line 175):

```python
        alert_id: uuid.UUID = alert.id
        created_at = alert.created_at or datetime.now(timezone.utc)
```

and after the `await db.commit()` that ends that `async with` block (line 202), before the Redis publish:

```python
    from worker import alert_iocs
    await alert_iocs.index_new_alert(
        alert_iocs.AlertMeta(alert_id=str(alert_id), group_id=group_id, severity=rule_match["level"],
                             hostname=hostname, agent_id=str(agent_id) if agent_id else None,
                             rule_title=rule_match["title"], created_at=created_at),
        source_ip, rule_match.get("matched_fields"),
    )
```

In `worker/worker/graph/triage_graph.py` `persist_node`, after the `set_alert_verdict` block:

```python
        if alert_id:
            asyncio.ensure_future(deps["set_alert_verdict"](alert_id, verdict))
        if alert_id and "index_alert_iocs" in deps:
            asyncio.ensure_future(deps["index_alert_iocs"](
                alert_id, state.get("decoded_fields"), getattr(state.get("enrichment"), "iocs", None), verdict,
            ))
```

In `worker/worker/ai_analyst.py`, add to the `deps={...}` of `build_triage_graph` (next to `"set_alert_verdict"`), with the import at the top of the function body that builds the graph:

```python
    from worker.alert_iocs import index_triaged_alert
```
```python
            "index_alert_iocs": index_triaged_alert,
```

In `worker/worker/main.py`, import next to `ensure_es_index` (line 33):

```python
from worker.alert_iocs import ensure_index as ensure_alert_iocs_index
```

and call it right after `await ensure_es_index()` (line 151):

```python
    await ensure_alert_iocs_index()
```

Update the spec section A "Writing" to match:

```markdown
### Writing

- `alert_manager.create_alert` indexes every new alert's indicators (`origin`
  `alert`/`event`). This must happen there: AI triage only runs for alerts at or
  above `ai_min_severity`.
- After AI triage, `persist_node` rewrites the alert's documents (same ids) with
  TI-extracted indicators (`origin=ti`) and `ai_verdict`.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/worker/test_alert_iocs.py tests/worker/test_ueba_ai_triage.py tests/worker/test_triage_rag.py -q`
Expected: all pass (14 in `test_alert_iocs.py`).

- [ ] **Step 5: Commit**

```bash
git add worker/worker/alert_iocs.py worker/worker/alert_manager.py worker/worker/graph/triage_graph.py \
  worker/worker/ai_analyst.py worker/worker/main.py tests/worker/test_alert_iocs.py \
  docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md
git commit -m "feat(iocs): index alert indicators at creation and after AI triage

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Retention delete and one-shot backfill

**Files:**
- Modify: `worker/worker/maintenance.py:40-51`
- Modify: `worker/worker/alert_iocs.py` (append)
- Modify: `worker/worker/main.py` (gather list)
- Test: `tests/worker/test_alert_iocs.py` (append), `tests/worker/test_alert_iocs_backfill.int.py` (create)

**Interfaces:**
- Consumes: Task 1 `collect`, `index_docs`, `delete_for_alerts`; Task 2 `_exclusions`, `meta_of`.
- Produces:
  - `maintenance._purge_alerts(days: int) -> int`
  - `alert_iocs.indicators_to_extracted(keys: list[str]) -> list[dict]`
  - `async alert_iocs.backfill(batch: int = 500) -> int`, `async alert_iocs.backfill_once() -> None`
  - Redis flag `siem:alert_iocs:backfilled`

- [ ] **Step 1: Write the failing tests**

Append to `tests/worker/test_alert_iocs.py`:

```python
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
```

Create `tests/worker/test_alert_iocs_backfill.int.py`:

```python
# tests/worker/test_alert_iocs_backfill.int.py
"""One-shot backfill of alert_iocs from Postgres (alerts.source_ip and linked
case indicators). Needs TEST_DATABASE_URL naming a disposable PostgreSQL; the
test gets its own schema, dropped afterwards."""
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import Alert, Case, CaseAlert


@pytest.fixture
async def sessions():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs disposable PostgreSQL TEST_DATABASE_URL")
    schema = "iocs_test_" + uuid4().hex
    admin = create_async_engine(url)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": f"{schema},public"}},
                                 execution_options={"schema_translate_map": {None: schema}})
    tables = {Alert.__table__, Case.__table__, CaseAlert.__table__}
    while True:
        dependencies = {fk.column.table for table in tables for fk in table.foreign_keys}
        if dependencies <= tables:
            break
        tables |= dependencies
    async with engine.begin() as connection:
        await connection.run_sync(lambda c: Base.metadata.create_all(c, tables=list(tables)))
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def test_backfill_indexes_old_alerts_once(sessions, monkeypatch):
    from worker import alert_iocs, database, redis_client, settings_cache
    async with sessions() as db:
        alerts = [Alert(title=f"a{i}", severity="high", group_id="blue", source_ip=ip)
                  for i, ip in enumerate(("45.33.32.1", "10.0.0.1", "45.33.32.3"))]
        db.add_all(alerts)
        await db.flush()
        case = Case(title="c", severity="high", status="open", group_id="blue", alert_id=alerts[0].id)
        db.add(case)
        await db.flush()
        db.add(CaseAlert(case_id=case.id, alert_id=alerts[1].id, status="linked", method="ai", reason="r",
                         confidence=0.9, indicators=["domain:c2.example"], accounts=[]))
        db.add(CaseAlert(case_id=case.id, alert_id=alerts[2].id, status="suggested", method="ai", reason="r",
                         confidence=0.5, indicators=["domain:maybe.example"], accounts=[]))
        await db.commit()

    flags, docs = {}, []

    async def get(key):
        return flags.get(key)

    async def set_(key, value):
        flags[key] = value

    async def get_redis():
        return SimpleNamespace(get=get, set=set_)

    async def index_docs(batch):
        docs.extend(batch)

    async def get_setting(key, default=""):
        return default

    monkeypatch.setattr(database, "AsyncSessionLocal", sessions)
    monkeypatch.setattr(redis_client, "get_redis", get_redis)
    monkeypatch.setattr(settings_cache, "get_setting", get_setting)
    monkeypatch.setattr(alert_iocs, "index_docs", index_docs)

    assert await alert_iocs.backfill(batch=2) == 3
    assert {(d["alert_id"], d["type"], d["value"], d["origin"]) for _, d in docs} == {
        (str(alerts[0].id), "ip", "45.33.32.1", "alert"),
        (str(alerts[1].id), "domain", "c2.example", "alert"),
        (str(alerts[2].id), "ip", "45.33.32.3", "alert"),
    }
    assert await alert_iocs.backfill(batch=2) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/worker/test_alert_iocs.py tests/worker/test_alert_iocs_backfill.int.py -q`
Expected: FAIL (`AttributeError: ... has no attribute 'indicators_to_extracted'`, `... '_purge_alerts'`, `... 'backfill'`).

- [ ] **Step 3: Write the implementation**

In `worker/worker/maintenance.py`, add the import `from worker import alert_iocs` with the other imports, add this function after `_purge_logs`:

```python
async def _purge_alerts(days: int) -> int:
    """Closed/resolved alerts older than `days`, with their alert_iocs documents."""
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            delete(Alert)
            .where(Alert.status.in_(["closed", "resolved"]))
            .where(Alert.created_at < cutoff)
            .returning(Alert.id)
        )
        deleted = [str(i) for i in result.scalars().all()]
        await db.commit()
    await alert_iocs.delete_for_alerts(deleted)
    return len(deleted)
```

and replace the inline alert purge in `maintenance_loop` (the `if alrt_days > 0: ... else:` block that sets `n_alrt`) with:

```python
            n_alrt = await _purge_alerts(alrt_days)
```

Append to `worker/worker/alert_iocs.py`:

```python
BACKFILL_FLAG = "siem:alert_iocs:backfilled"
_KEY_TYPES = {"ip": "ipv4", "domain": "domain", "url": "url"}
_KEY_HASHES = {64: "hash_sha256", 40: "hash_sha1", 32: "hash_md5"}


def indicators_to_extracted(keys: list[str]) -> list[dict]:
    """case_alerts.indicators ("ip:…", "domain:…", "url:…", "hash:…") as extracted items."""
    out = []
    for key in keys or []:
        kind, _, value = str(key).partition(":")
        if not value:
            continue
        mapped = _KEY_HASHES.get(len(value)) if kind == "hash" else _KEY_TYPES.get(kind)
        if mapped:
            out.append({"type": mapped, "value": value})
    return out


async def backfill(batch: int = 500) -> int:
    """Index alerts that predate alert_iocs, once (Redis flag). Returns documents written."""
    from collections import defaultdict
    from sqlalchemy import select, tuple_
    from worker import database, redis_client
    from worker.models import Alert, CaseAlert

    redis = await redis_client.get_redis()
    if await redis.get(BACKFILL_FLAG):
        return 0
    exclusions = await _exclusions()
    total, cursor = 0, None
    while True:
        async with database.AsyncSessionLocal() as db:
            query = select(Alert).order_by(Alert.created_at, Alert.id).limit(batch)
            if cursor is not None:
                query = query.where(tuple_(Alert.created_at, Alert.id) > cursor)
            alerts = (await db.execute(query)).scalars().all()
            if not alerts:
                break
            links = (await db.execute(
                select(CaseAlert.alert_id, CaseAlert.indicators)
                .where(CaseAlert.alert_id.in_([a.id for a in alerts]), CaseAlert.status == "linked")
            )).all()
        indicators: dict = defaultdict(list)
        for alert_id, keys in links:
            indicators[alert_id].extend(keys or [])
        docs = []
        for alert in alerts:
            docs += collect(meta_of(alert), alert.source_ip, None, indicators_to_extracted(indicators[alert.id]),
                            exclusions, extracted_origin="alert")
        await index_docs(docs)
        total += len(docs)
        cursor = (alerts[-1].created_at, alerts[-1].id)
    await redis.set(BACKFILL_FLAG, "1")
    log.info("alert_iocs_backfilled", docs=total)
    return total


async def backfill_once() -> None:
    try:
        await backfill()
    except Exception:
        log.exception("alert_iocs_backfill_failed")
```

In `worker/worker/main.py`, add `from worker.alert_iocs import backfill_once as alert_iocs_backfill` with the imports and append `alert_iocs_backfill()` to the `asyncio.gather(...)` call that starts the loops (it returns once done; failures are logged inside).

- [ ] **Step 4: Run tests to verify they pass**

Run (with the test DB env from "Test commands"):
`python3 -m pytest tests/worker/test_alert_iocs.py tests/worker/test_alert_iocs_backfill.int.py -q`
Expected: all pass (16 + 1).

- [ ] **Step 5: Commit**

```bash
git add worker/worker/maintenance.py worker/worker/alert_iocs.py worker/worker/main.py \
  tests/worker/test_alert_iocs.py tests/worker/test_alert_iocs_backfill.int.py
git commit -m "feat(iocs): purge indicator docs with their alerts and backfill old alerts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: IoC API

**Files:**
- Modify: `server-api/app/core/es_client.py` (append)
- Create: `server-api/app/api/routes/iocs.py`
- Modify: `server-api/app/main.py` (import + router list near line 535)
- Modify: spec section A "API" (drill-down path)
- Test: `tests/server-api/test_iocs_api.int.py`

**Interfaces:**
- Consumes: the `alert_iocs` document fields from Task 1.
- Produces (HTTP, used by Task 5):
  - `GET /api/iocs?type=&q=&since=&until=&sort=last_seen|alerts&limit=&offset=` →
    `{"total": int, "type_counts": {type: int}, "items": [{"type", "value", "alerts", "hosts", "first_seen", "last_seen", "max_severity", "blocked"}]}`
  - `GET /api/iocs/alerts?type=&value=&limit=&offset=` →
    `{"total": int, "items": [{"id", "title", "severity", "status", "hostname", "created_at", "ai_verdict"}]}`
  - `es_client.search_iocs(body: dict) -> dict`

- [ ] **Step 1: Write the failing tests**

`tests/server-api/test_iocs_api.int.py`:

```python
# tests/server-api/test_iocs_api.int.py
"""Threat IoCs API: group scoping of every Elasticsearch query, bucket parsing,
and drill-down that never returns another group's alerts."""
import httpx
import pytest
from fastapi import FastAPI


@pytest.fixture
async def iocs_api(evidence_api, monkeypatch):
    from app.api.routes import iocs
    from app.core import es_client
    from app.core.database import get_db
    from app.core.deps import get_current_user

    bodies, reply = [], {"value": {}}

    async def search_iocs(body):
        bodies.append(body)
        return reply["value"]

    async def database():
        async with evidence_api.sessions() as db:
            yield db

    monkeypatch.setattr(es_client, "search_iocs", search_iocs)
    evidence_api.user = evidence_api.make_user(perms=("alerts:read",))
    app = FastAPI()
    app.include_router(iocs.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api, evidence_api.bodies, evidence_api.reply = client, bodies, reply
        yield evidence_api


BUCKETS = {"aggregations": {
    "types": {"buckets": [{"key": "url", "doc_count": 3}, {"key": "ip", "doc_count": 5}]},
    "matched": {"count": {"value": 1}, "iocs": {"buckets": [{
        "key": "url:http://evil.example/a:b", "alerts": {"value": 2}, "hosts": {"value": 1},
        "first_seen": {"value_as_string": "2026-11-01T00:00:00.000Z"},
        "last_seen": {"value_as_string": "2026-11-02T00:00:00.000Z"}, "max_severity": {"value": 4.0},
    }]}},
}}


def _filters(body):
    return body["query"]["bool"]["filter"]


async def test_list_is_scoped_to_the_callers_group_and_parsed(iocs_api):
    iocs_api.reply["value"] = BUCKETS
    r = await iocs_api.api.get("/api/iocs", params={"type": "url", "q": "Evil"})
    assert r.status_code == 200, r.text
    body = iocs_api.bodies[0]
    assert {"term": {"group_id": "blue"}} in _filters(body)
    assert {"wildcard": {"value": {"value": "*evil*", "case_insensitive": True}}} in _filters(body)
    assert body["aggs"]["matched"]["filter"] == {"term": {"type": "url"}}
    assert r.json() == {"total": 1, "type_counts": {"url": 3, "ip": 5}, "items": [{
        "type": "url", "value": "http://evil.example/a:b", "alerts": 2, "hosts": 1,
        "first_seen": "2026-11-01T00:00:00.000Z", "last_seen": "2026-11-02T00:00:00.000Z",
        "max_severity": "critical", "blocked": None}]}


async def test_superadmin_sees_every_group(iocs_api):
    iocs_api.user = iocs_api.make_user(role="superadmin")
    assert (await iocs_api.api.get("/api/iocs")).status_code == 200
    assert not any("group_id" in str(f) for f in _filters(iocs_api.bodies[0]))


async def test_sort_window_and_page_reach_the_query(iocs_api):
    r = await iocs_api.api.get("/api/iocs", params={"sort": "alerts", "since": "2026-11-01T00:00:00Z",
                                                     "limit": 10, "offset": 20, "q": "a*b"})
    assert r.status_code == 200
    body = iocs_api.bodies[0]
    terms = body["aggs"]["matched"]["aggs"]["iocs"]
    assert terms["terms"]["order"] == {"alerts": "desc"}
    assert terms["aggs"]["page"]["bucket_sort"] == {"from": 20, "size": 10}
    assert {"range": {"created_at": {"gte": "2026-11-01T00:00:00+00:00"}}} in _filters(body)
    assert {"wildcard": {"value": {"value": "*a\\*b*", "case_insensitive": True}}} in _filters(body)


async def test_missing_index_returns_an_empty_list(iocs_api):
    r = await iocs_api.api.get("/api/iocs")
    assert r.json() == {"total": 0, "type_counts": {}, "items": []}


async def test_unknown_type_and_missing_permission_are_rejected(iocs_api):
    assert (await iocs_api.api.get("/api/iocs", params={"type": "mutex"})).status_code == 422
    iocs_api.user = iocs_api.make_user(perms=())
    assert (await iocs_api.api.get("/api/iocs")).status_code == 403


async def test_drill_down_never_returns_another_groups_alert(iocs_api):
    from app.models.models import Alert
    async with iocs_api.sessions() as db:
        blue = Alert(title="Beacon", severity="high", group_id="blue", hostname="blue-host")
        red = Alert(title="Beacon", severity="high", group_id="red", hostname="red-host")
        db.add_all([blue, red])
        await db.commit()
    iocs_api.reply["value"] = {"aggregations": {"ids": {"buckets": [{"key": str(red.id)}, {"key": str(blue.id)}]}}}
    r = await iocs_api.api.get("/api/iocs/alerts", params={"type": "domain", "value": "c2.example"})
    assert r.status_code == 200, r.text
    assert [a["id"] for a in r.json()["items"]] == [str(blue.id)]
    filters = _filters(iocs_api.bodies[0])
    assert {"term": {"type": "domain"}} in filters and {"term": {"value": "c2.example"}} in filters
    assert {"term": {"group_id": "blue"}} in filters
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/server-api/test_iocs_api.int.py -q`
Expected: ERROR `ModuleNotFoundError: No module named 'app.api.routes.iocs'` (skips if `TEST_DATABASE_URL` is unset: set it).

- [ ] **Step 3: Write the implementation**

Append to `server-api/app/core/es_client.py`:

```python
IOCS_INDEX = "alert_iocs"


async def search_iocs(body: dict) -> dict:
    """Raw search on alert_iocs (written by worker/worker/alert_iocs.py). {} before the index exists."""
    resp = await _get_client().post(f"/{IOCS_INDEX}/_search", json=body)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()
```

Create `server-api/app/api/routes/iocs.py`:

```python
# server-api/app/api/routes/iocs.py
"""Threat IoCs: attacker indicators recorded in alerts (Elasticsearch index
alert_iocs, written by worker/worker/alert_iocs.py), aggregated per indicator.
Every query carries the caller's group filter."""
import re
from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import es_client
from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.models.models import Alert

router = APIRouter(prefix="/api/iocs", tags=["iocs"])

IocType = Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email"]
SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"]
MAX_BUCKETS = 1000
MAX_DRILL_ALERTS = 200


def _wildcard(q: str) -> str:
    return "*" + re.sub(r"([\\*?])", r"\\\1", q.strip().lower()) + "*"


def _filters(group: Optional[str], q: str, since: Optional[datetime], until: Optional[datetime]) -> list[dict]:
    filters: list[dict] = []
    if group is not None:
        filters.append({"term": {"group_id": group}})
    if q.strip():
        filters.append({"wildcard": {"value": {"value": _wildcard(q), "case_insensitive": True}}})
    window = {k: v.isoformat() for k, v in (("gte", since), ("lte", until)) if v}
    if window:
        filters.append({"range": {"created_at": window}})
    return filters


def _value_of(agg: dict) -> Optional[str]:
    return agg.get("value_as_string") if agg and agg.get("value") is not None else None


@router.get("")
async def list_iocs(
    type: Optional[IocType] = None,
    q: str = Query("", max_length=200),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    sort: Literal["last_seen", "alerts"] = "last_seen",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=MAX_BUCKETS - 1),
    _=Depends(require_permission("alerts:read")),
    group: Optional[str] = Depends(get_scoped_group),
):
    body = {
        "size": 0,
        "query": {"bool": {"filter": _filters(group, q, since, until)}},
        "aggs": {
            "types": {"terms": {"field": "type", "size": 10}},
            "matched": {
                "filter": {"term": {"type": type}} if type else {"match_all": {}},
                "aggs": {
                    "count": {"cardinality": {"field": "ioc_key"}},
                    "iocs": {
                        "terms": {"field": "ioc_key", "size": MAX_BUCKETS, "order": {sort: "desc"}},
                        "aggs": {
                            "alerts": {"cardinality": {"field": "alert_id"}},
                            "hosts": {"cardinality": {"field": "hostname"}},
                            "first_seen": {"min": {"field": "created_at"}},
                            "last_seen": {"max": {"field": "created_at"}},
                            "max_severity": {"max": {"field": "severity_rank"}},
                            "page": {"bucket_sort": {"from": offset, "size": limit}},
                        },
                    },
                },
            },
        },
    }
    aggs = (await es_client.search_iocs(body)).get("aggregations") or {}
    matched = aggs.get("matched") or {}
    items = []
    for bucket in (matched.get("iocs") or {}).get("buckets", []):
        kind, _, value = bucket["key"].partition(":")
        rank = (bucket.get("max_severity") or {}).get("value")
        items.append({
            "type": kind, "value": value,
            "alerts": int(bucket["alerts"]["value"]), "hosts": int(bucket["hosts"]["value"]),
            "first_seen": _value_of(bucket.get("first_seen")), "last_seen": _value_of(bucket.get("last_seen")),
            "max_severity": SEVERITY_NAMES[int(rank)] if rank is not None and 0 <= int(rank) < 5 else None,
            "blocked": None,  # Web Protection (stage B1) fills this
        })
    return {
        "total": min(int((matched.get("count") or {}).get("value", 0)), MAX_BUCKETS),
        "type_counts": {b["key"]: b["doc_count"] for b in (aggs.get("types") or {}).get("buckets", [])},
        "items": items,
    }


@router.get("/alerts")
async def ioc_alerts(
    type: IocType,
    value: str = Query(..., min_length=1, max_length=4096),
    limit: int = Query(50, ge=1, le=MAX_DRILL_ALERTS),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_permission("alerts:read")),
    group: Optional[str] = Depends(get_scoped_group),
):
    filters = [{"term": {"type": type}}, {"term": {"value": value}}]
    if group is not None:
        filters.append({"term": {"group_id": group}})
    result = await es_client.search_iocs({
        "size": 0, "query": {"bool": {"filter": filters}},
        "aggs": {"ids": {"terms": {"field": "alert_id", "size": MAX_DRILL_ALERTS, "order": {"latest": "desc"}},
                         "aggs": {"latest": {"max": {"field": "created_at"}}}}},
    })
    ids = []
    for bucket in ((result.get("aggregations") or {}).get("ids") or {}).get("buckets", []):
        try:
            ids.append(UUID(bucket["key"]))
        except ValueError:
            continue
    if not ids:
        return {"total": 0, "items": []}
    query = select(Alert).where(Alert.id.in_(ids))
    if group is not None:  # Postgres is the authority: never trust the index for scoping alone
        query = query.where(Alert.group_id == group)
    alerts = (await db.execute(query.order_by(Alert.created_at.desc()))).scalars().all()
    return {"total": len(alerts), "items": [{
        "id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status, "hostname": a.hostname,
        "created_at": a.created_at.isoformat() if a.created_at else None, "ai_verdict": a.ai_verdict,
    } for a in alerts[offset:offset + limit]]}
```

Register in `server-api/app/main.py`: add next to the other route imports

```python
from app.api.routes.iocs import router as iocs_router
```

and add `iocs_router,` to the `for router in [...]` list (line ~535).

Update the spec section A "API" drill-down line to:
`- GET /api/iocs/alerts?type=&value=&limit=&offset=` (query parameters: URL values contain `/`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/server-api/test_iocs_api.int.py -q` then `$PY -m pytest tests/server-api -q`
Expected: 6 passed; full server-api suite green under pytest-asyncio 0.24.

If the tests error with "There is no current event loop" under `$PY`, add to the test module (same fix as `test_soar_case_events.py` on `feat/case-soar-events`):

```python
import asyncio


@pytest.fixture(autouse=True)
def _current_loop(event_loop):
    asyncio.set_event_loop(event_loop)
```

- [ ] **Step 5: Commit**

```bash
git add server-api/app/core/es_client.py server-api/app/api/routes/iocs.py server-api/app/main.py \
  tests/server-api/test_iocs_api.int.py docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md
git commit -m "feat(iocs): group-scoped Threat IoCs API over alert_iocs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Threat IoCs dashboard page

**Files:**
- Create: `dashboard/src/hooks/useIocs.ts`
- Create: `dashboard/src/pages/ThreatIocsPage.tsx`
- Modify: `dashboard/src/App.tsx` (import + route next to `/malware-hashes`, line ~90)
- Modify: `dashboard/src/components/AppSidebar.tsx` (Investigation group)

**Interfaces:**
- Consumes: Task 4 HTTP responses; `useAddMalwareHashes` (`dashboard/src/hooks/useMalwareHashes.ts`: body `{hashes, label, reference}`), `useStartHunt` (`dashboard/src/hooks/useHunts.ts`: body `{ioc_type: 'ip'|'hostname'|'user'|'hash', ioc_value}`).
- Produces: route `/threat-iocs`.

- [ ] **Step 1: Write the hook**

`dashboard/src/hooks/useIocs.ts`:

```ts
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export type IocType = 'ip' | 'domain' | 'url' | 'sha256' | 'sha1' | 'md5' | 'email'
export const IOC_TYPES: IocType[] = ['ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email']

export interface Ioc {
  type: IocType
  value: string
  alerts: number
  hosts: number
  first_seen: string | null
  last_seen: string | null
  max_severity: string | null
  blocked: boolean | null
}

export interface IocList {
  total: number
  type_counts: Partial<Record<IocType, number>>
  items: Ioc[]
}

export interface IocAlert {
  id: string
  title: string
  severity: string
  status: string
  hostname: string | null
  created_at: string | null
  ai_verdict: string | null
}

export interface IocFilter {
  type: IocType | ''
  q: string
  days: number
  sort: 'last_seen' | 'alerts'
  offset: number
}

export const IOC_PAGE = 50

export function useIocs(f: IocFilter) {
  return useQuery<IocList>({
    queryKey: ['iocs', f],
    queryFn: () => api.get('/api/iocs', {
      params: {
        type: f.type || undefined,
        q: f.q || undefined,
        since: f.days ? new Date(Date.now() - f.days * 86400000).toISOString() : undefined,
        sort: f.sort,
        limit: IOC_PAGE,
        offset: f.offset,
      },
    }).then(r => r.data),
    placeholderData: keepPreviousData,
  })
}

export function useIocAlerts(ioc: Pick<Ioc, 'type' | 'value'> | null) {
  return useQuery<{ total: number; items: IocAlert[] }>({
    queryKey: ['iocs', 'alerts', ioc?.type, ioc?.value],
    queryFn: () => api.get('/api/iocs/alerts', { params: { type: ioc!.type, value: ioc!.value, limit: 50 } })
      .then(r => r.data),
    enabled: !!ioc,
  })
}
```

- [ ] **Step 2: Write the page**

`dashboard/src/pages/ThreatIocsPage.tsx`:

```tsx
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Check, Copy, Crosshair, Loader2, Search, ShieldX, X } from 'lucide-react'
import { IOC_PAGE, IOC_TYPES, type Ioc, type IocFilter, type IocType, useIocAlerts, useIocs } from '@/hooks/useIocs'
import { useAddMalwareHashes } from '@/hooks/useMalwareHashes'
import { useStartHunt } from '@/hooks/useHunts'

const TYPE_LABEL: Record<IocType, string> = {
  ip: 'IP', domain: 'Domain', url: 'URL', sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', email: 'Email',
}
const WINDOWS = [{ days: 1, label: '24 h' }, { days: 7, label: '7 days' }, { days: 30, label: '30 days' },
  { days: 90, label: '90 days' }, { days: 0, label: 'All time' }]
const SEVERITY_CLASS: Record<string, string> = {
  critical: 'text-red-500', high: 'text-orange-500', medium: 'text-yellow-500', low: 'text-blue-400', info: 'text-muted-foreground',
}

function ago(iso: string | null): string {
  if (!iso) return '—'
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 90) return 'just now'
  if (s < 5400) return `${Math.round(s / 60)} min ago`
  if (s < 172800) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} days ago`
}

function huntType(type: IocType): 'ip' | 'hash' | null {
  if (type === 'ip') return 'ip'
  return type === 'sha256' || type === 'sha1' || type === 'md5' ? 'hash' : null
}

function Detail({ ioc, onClose }: { ioc: Ioc; onClose: () => void }) {
  const { data, isLoading } = useIocAlerts(ioc)
  const hunt = useStartHunt()
  const addHash = useAddMalwareHashes()
  const navigate = useNavigate()
  const kind = huntType(ioc.type)
  return (
    <aside className="rounded-lg border border-border p-4 space-y-3 lg:w-96 shrink-0">
      <div className="flex items-start gap-2">
        <div className="min-w-0">
          <div className="text-xs text-muted-foreground">{TYPE_LABEL[ioc.type]}</div>
          <div className="font-mono text-sm break-all">{ioc.value}</div>
        </div>
        <button onClick={onClose} aria-label="Close" className="ml-auto p-1 rounded hover:bg-muted"><X size={14} /></button>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div><div className="text-muted-foreground">Alerts</div>{ioc.alerts}</div>
        <div><div className="text-muted-foreground">Hosts</div>{ioc.hosts}</div>
        <div><div className="text-muted-foreground">First seen</div>{ago(ioc.first_seen)}</div>
        <div><div className="text-muted-foreground">Last seen</div>{ago(ioc.last_seen)}</div>
      </div>
      <div className="flex flex-wrap gap-2">
        {kind && (
          <button disabled={hunt.isPending}
            onClick={() => hunt.mutate({ ioc_type: kind, ioc_value: ioc.value }, { onSuccess: () => navigate('/hunts') })}
            className="text-xs px-2 py-1 rounded border border-border hover:bg-muted inline-flex items-center gap-1">
            <Crosshair size={12} /> Hunt
          </button>
        )}
        {ioc.type === 'sha256' && (
          <button disabled={addHash.isPending || addHash.isSuccess}
            onClick={() => addHash.mutate({ hashes: [ioc.value], label: '', reference: 'Threat IoCs' })}
            className="text-xs px-2 py-1 rounded border border-border hover:bg-muted inline-flex items-center gap-1">
            <ShieldX size={12} /> {addHash.isSuccess ? 'Added to malware hashes' : 'Add to malware hashes'}
          </button>
        )}
      </div>
      <div className="text-xs font-semibold">Alerts with this indicator</div>
      {isLoading ? <Loader2 size={14} className="animate-spin" /> : !data?.items.length ? (
        <p className="text-xs text-muted-foreground">No alerts visible to you.</p>
      ) : (
        <ul className="space-y-1">
          {data.items.map(a => (
            <li key={a.id} className="text-xs border-t border-border pt-1">
              <Link to={`/alerts/${a.id}`} className="hover:underline font-medium">{a.title}</Link>
              <div className="text-muted-foreground">
                <span className={SEVERITY_CLASS[a.severity] ?? ''}>{a.severity}</span>
                {' · '}{a.hostname ?? 'no host'}{' · '}{ago(a.created_at)}{a.ai_verdict ? ` · AI: ${a.ai_verdict}` : ''}
              </div>
            </li>
          ))}
        </ul>
      )}
    </aside>
  )
}

export default function ThreatIocsPage() {
  const [filter, setFilter] = useState<IocFilter>({ type: '', q: '', days: 30, sort: 'last_seen', offset: 0 })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Ioc | null>(null)
  const [copied, setCopied] = useState('')
  const { data, isLoading, isFetching } = useIocs(filter)
  const update = (patch: Partial<IocFilter>) => setFilter(f => ({ ...f, offset: 0, ...patch }))
  const counts = data?.type_counts ?? {}
  const all = Object.values(counts).reduce((sum, n) => sum + (n ?? 0), 0)

  const copy = (value: string) => {
    navigator.clipboard?.writeText(value)
    setCopied(value)
    setTimeout(() => setCopied(''), 1500)
  }

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-bold">Threat IoCs</h1>
        <p className="text-sm text-muted-foreground">Attacker indicators recorded in your alerts.</p>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-border" role="tablist">
        {[{ key: '' as const, label: 'All', count: all }, ...IOC_TYPES.map(t => ({ key: t, label: TYPE_LABEL[t], count: counts[t] ?? 0 }))]
          .map(tab => (
            <button key={tab.key || 'all'} role="tab" aria-selected={filter.type === tab.key}
              onClick={() => { update({ type: tab.key }); setSelected(null) }}
              className={`px-3 py-1.5 text-sm border-b-2 -mb-px ${filter.type === tab.key
                ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
              {tab.label} <span className="text-xs text-muted-foreground">{tab.count.toLocaleString()}</span>
            </button>
          ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <form onSubmit={e => { e.preventDefault(); update({ q: search }) }} className="flex items-center gap-1">
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search indicator"
            aria-label="Search indicator" className="bg-muted border border-border rounded px-2 py-1.5 text-sm w-64" />
          <button type="submit" aria-label="Search" className="p-1.5 rounded border border-border hover:bg-muted"><Search size={14} /></button>
        </form>
        <select value={filter.days} onChange={e => update({ days: Number(e.target.value) })} aria-label="Time window"
          className="bg-muted border border-border rounded px-2 py-1.5 text-sm">
          {WINDOWS.map(w => <option key={w.days} value={w.days}>{w.label}</option>)}
        </select>
        <select value={filter.sort} onChange={e => update({ sort: e.target.value as IocFilter['sort'] })} aria-label="Sort"
          className="bg-muted border border-border rounded px-2 py-1.5 text-sm">
          <option value="last_seen">Most recent</option>
          <option value="alerts">Most alerts</option>
        </select>
        {isFetching && <Loader2 size={14} className="animate-spin text-muted-foreground" />}
        <span className="text-xs text-muted-foreground ml-auto">{data ? `${data.total.toLocaleString()} indicators` : ''}</span>
      </div>

      <div className="flex flex-col lg:flex-row gap-4 items-start">
        <div className="flex-1 min-w-0 space-y-2">
          {isLoading ? <Loader2 size={16} className="animate-spin" /> : !data?.items.length ? (
            <p className="text-sm text-muted-foreground">No indicators in this window.</p>
          ) : (
            <div className="rounded-lg border border-border overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                  <tr>
                    <th className="text-left px-3 py-2">Indicator</th>
                    <th className="text-right px-3 py-2">Alerts</th>
                    <th className="text-right px-3 py-2">Hosts</th>
                    <th className="text-left px-3 py-2">Severity</th>
                    <th className="text-left px-3 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map(ioc => (
                    <tr key={`${ioc.type}:${ioc.value}`} onClick={() => setSelected(ioc)}
                      className={`border-t border-border cursor-pointer hover:bg-muted/40 ${selected?.value === ioc.value && selected.type === ioc.type ? 'bg-muted/60' : ''}`}>
                      <td className="px-3 py-2 max-w-md">
                        <div className="text-xs text-muted-foreground">{TYPE_LABEL[ioc.type]}</div>
                        <button onClick={e => { e.stopPropagation(); copy(ioc.value) }} title={ioc.value}
                          className="font-mono text-xs inline-flex items-center gap-1 hover:underline max-w-full">
                          <span className="truncate">{ioc.value}</span>
                          {copied === ioc.value ? <Check size={11} className="text-primary shrink-0" /> : <Copy size={11} className="opacity-50 shrink-0" />}
                        </button>
                      </td>
                      <td className="px-3 py-2 text-right tabular-nums">{ioc.alerts}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{ioc.hosts}</td>
                      <td className={`px-3 py-2 text-xs ${SEVERITY_CLASS[ioc.max_severity ?? ''] ?? ''}`}>{ioc.max_severity ?? '—'}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{ago(ioc.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {data && data.total > IOC_PAGE && (
            <div className="flex items-center gap-2 text-xs">
              <button disabled={filter.offset === 0} onClick={() => setFilter(f => ({ ...f, offset: Math.max(0, f.offset - IOC_PAGE) }))}
                className="px-2 py-1 rounded border border-border disabled:opacity-40">Previous</button>
              <span className="text-muted-foreground">
                {filter.offset + 1}–{Math.min(filter.offset + IOC_PAGE, data.total)} of {data.total.toLocaleString()}
              </span>
              <button disabled={filter.offset + IOC_PAGE >= data.total} onClick={() => setFilter(f => ({ ...f, offset: f.offset + IOC_PAGE }))}
                className="px-2 py-1 rounded border border-border disabled:opacity-40">Next</button>
            </div>
          )}
          {data && data.total >= 1000 && (
            <p className="text-xs text-muted-foreground">Showing the top 1,000 indicators of this window. Search or narrow the window to see others.</p>
          )}
        </div>
        {selected && <Detail ioc={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Add the route and menu entry**

`dashboard/src/App.tsx`: add with the other page imports

```tsx
import ThreatIocsPage from '@/pages/ThreatIocsPage'
```

and next to `<Route path="/malware-hashes" element={<MalwareHashesPage />} />`:

```tsx
            <Route path="/threat-iocs" element={<ThreatIocsPage />} />
```

`dashboard/src/components/AppSidebar.tsx`: add `Fingerprint` to the `lucide-react` import list and this item in the `Investigation` group after `Threat hunting`:

```tsx
    { to: '/threat-iocs', label: 'Threat IoCs', icon: Fingerprint },
```

- [ ] **Step 4: Typecheck and build**

Run: `cd dashboard && npx tsc --noEmit -p . && npx vite build`
Expected: exit 0, no type errors.

- [ ] **Step 5: Check it in the browser**

Run the dev stack (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`), open `/threat-iocs` with the `/browse` skill, confirm: tabs show counts, a row opens the detail panel with alerts linking to `/alerts/<id>`, Hunt appears only for IP/hashes, "Add to malware hashes" only for SHA-256, and the layout has no horizontal scroll at 390 px width.

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/hooks/useIocs.ts dashboard/src/pages/ThreatIocsPage.tsx dashboard/src/App.tsx \
  dashboard/src/components/AppSidebar.tsx
git commit -m "feat(dashboard): Threat IoCs page

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Final verification (after Task 5)

```bash
$PY -m pytest tests/server-api -q
$PY -m pytest tests/worker worker/tests -q --ignore=tests/worker/test_pipeline.int.test.py \
  --deselect worker/tests/test_rag.py::test_embed_text_returns_384_dimensions \
  --deselect worker/tests/test_rag.py::test_embed_text_different_inputs_differ
cd dashboard && npx tsc --noEmit -p . && npx vite build
```

All green, then push the branch and open a draft PR against `feature/siem-implementation`.
