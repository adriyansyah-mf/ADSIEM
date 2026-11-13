# tests/worker/test_soar_new_nodes.py
"""SOAR investigation/containment nodes without a database: Alert Event, Log
Search, Endpoint Scan, Threat Hunt and Block IOC. Validation, plus each
handler against fakes for the DB session, Elasticsearch and the agent queue."""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker.soar import nodes  # noqa: E402
from worker.soar.graph import GraphError, validate  # noqa: E402

SHA = "a" * 64
CTX = {"trigger": {"alert_id": str(uuid.uuid4()), "group_id": "blue", "hostname": "dvwa-01",
                   "source_ip": "203.0.113.7", "rule_title": "Web shell"},
       "run": {"id": "run-1"}, "steps": {}}


def graph(*nodes_):
    ns = [{"id": "trigger", "type": "trigger", "params": {"event": "alert.created"}}]
    edges, prev = [], "trigger"
    for i, (t, p) in enumerate(nodes_):
        nid = f"n{i}"
        ns.append({"id": nid, "type": t, "params": p})
        edges.append({"from": prev, "output": "main", "to": nid})
        prev = nid
    return {"nodes": ns, "edges": edges}


# ─── validation ─────────────────────────────────────────────────────────────

def test_valid_graph_with_every_new_node():
    g = validate(graph(
        ("alert_event", {}),
        ("log_search", {"field": "source_ip", "value": "{{ trigger.source_ip }}", "minutes": 60}),
        ("scan", {"operation": "file_scan", "kind": "paths", "paths": "{{ steps.n0.file_path }}"}),
        ("scan", {"operation": "memory_scan", "pid": "{{ steps.n0.pid }}"}),
        ("hunt", {"ioc_type": "ip", "ioc_value": "{{ trigger.source_ip }}"}),
        ("block_ioc", {"operation": "prevention_rule", "rule_type": "hash", "action": "block", "value": "{{ steps.n0.sha256 }}"}),
    ))
    assert [n["type"] for n in g["nodes"]][1:] == ["alert_event", "log_search", "scan", "scan", "hunt", "block_ioc"]


@pytest.mark.parametrize("node,needle", [
    (("log_search", {"field": "password", "value": "x"}), "field must be one of"),
    (("log_search", {"field": "source_ip", "value": ""}), "value is required"),
    (("log_search", {"field": "source_ip", "value": "x", "minutes": 0}), "minutes must be between"),
    (("scan", {"operation": "format_disk"}), "operation must be one of"),
    (("scan", {"operation": "file_scan", "kind": "paths"}), "paths is required"),
    (("scan", {"operation": "yara_scan"}), "path is required"),
    (("hunt", {"ioc_type": "url", "ioc_value": "x"}), "ioc_type must be one of"),
    (("hunt", {"ioc_type": "ip"}), "ioc_value is required"),
    (("block_ioc", {"operation": "delete_everything", "value": "x"}), "operation must be one of"),
    (("block_ioc", {"operation": "prevention_rule", "rule_type": "parent", "value": "x"}), "rule_type must be one of"),
    (("block_ioc", {"operation": "prevention_rule", "action": "kill", "value": "x"}), "action must be block or detect"),
    (("block_ioc", {"operation": "malware_hash"}), "value is required"),
])
def test_invalid_params_are_rejected(node, needle):
    with pytest.raises(GraphError) as exc:
        validate(graph(node))
    assert any(needle in e for e in exc.value.errors), exc.value.errors


# ─── fakes ──────────────────────────────────────────────────────────────────

class Result:
    def __init__(self, value=None, values=()):
        self.value, self.values = value, list(values)

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return SimpleNamespace(all=lambda: self.values)


class Session:
    def __init__(self, results=()):
        self.results, self.added, self.executed, self.commits = list(results), [], [], 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, stmt, params=None):
        self.executed.append((stmt, params))
        return self.results.pop(0) if self.results else Result()

    def add(self, obj):
        if getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        self.added.append(obj)

    async def commit(self):
        self.commits += 1


@pytest.fixture
def notes(monkeypatch):
    seen = []

    async def note(ctx, content):
        seen.append(content)
    monkeypatch.setattr(nodes, "_note", note)
    return seen


def use_session(monkeypatch, session):
    monkeypatch.setattr(nodes, "AsyncSessionLocal", lambda: session)


# ─── Alert Event ────────────────────────────────────────────────────────────

def test_alert_event_returns_decoded_fields_and_shortcuts(monkeypatch):
    event_id = uuid.uuid4()
    use_session(monkeypatch, Session([Result(SimpleNamespace(event_id=event_id, group_id="blue"))]))
    queries = []

    async def es(query, size, sort=None):
        queries.append(query)
        return [{"id": str(event_id), "log_type": "linux_process_exec", "agent_id": "ag-1", "raw_message": "x",
                 "decoded_fields": {"ProcessId": "4242", "Image": "/usr/bin/dash", "CommandLine": "sh -c id",
                                    "file.hash.sha256": SHA}}]
    monkeypatch.setattr(nodes, "_es_search", es)
    out = asyncio.run(nodes.run_alert_event({}, {}, CTX))
    assert out.output == "main"
    assert (out.data["pid"], out.data["process"], out.data["command_line"], out.data["sha256"]) == \
        ("4242", "/usr/bin/dash", "sh -c id", SHA)
    assert out.data["fields"]["ProcessId"] == "4242"
    # the ES lookup is pinned to the run's group
    assert {"term": {"group_id": "blue"}} in queries[0]["bool"]["filter"]


def test_alert_event_refuses_other_groups_and_alerts_without_event(monkeypatch):
    use_session(monkeypatch, Session([Result(SimpleNamespace(event_id=uuid.uuid4(), group_id="red"))]))
    with pytest.raises(nodes.NodeError, match="not found"):
        asyncio.run(nodes.run_alert_event({}, {}, CTX))
    use_session(monkeypatch, Session([Result(SimpleNamespace(event_id=None, group_id="blue"))]))
    with pytest.raises(nodes.NodeError, match="no source event"):
        asyncio.run(nodes.run_alert_event({}, {}, CTX))


# ─── Log Search ─────────────────────────────────────────────────────────────

def _capture_es(monkeypatch, count):
    seen = {}

    async def es_count(query):
        seen["query"] = query
        return count

    async def es_search(query, size, sort=None):
        return [{"created_at": "2026-11-04T05:00:00Z", "log_type": "apache_access", "raw_message": "GET /"}]
    monkeypatch.setattr(nodes, "_es_count", es_count)
    monkeypatch.setattr(nodes, "_es_search", es_search)
    return seen


def test_log_search_counts_by_field_in_group_and_window(monkeypatch):
    seen = _capture_es(monkeypatch, 17)
    out = asyncio.run(nodes.run_log_search({}, {"field": "source_ip", "value": "203.0.113.7", "minutes": 30,
                                                 "log_type": "apache_access"}, CTX))
    assert out.data["count"] == 17 and len(out.data["hits"]) == 1
    f = seen["query"]["bool"]["filter"]
    assert {"term": {"group_id": "blue"}} in f
    assert {"range": {"created_at": {"gte": "now-30m"}}} in f
    assert {"term": {"source_ip": "203.0.113.7"}} in f and {"term": {"log_type": "apache_access"}} in f


def test_log_search_text_and_hostname(monkeypatch):
    seen = _capture_es(monkeypatch, 0)
    out = asyncio.run(nodes.run_log_search({}, {"field": "text", "value": "UNION SELECT", "minutes": 5}, CTX))
    assert {"match_phrase": {"raw_message": "UNION SELECT"}} in seen["query"]["bool"]["filter"]
    assert out.data["hits"] == []  # no sample fetched for a zero count

    agent_id = uuid.uuid4()
    use_session(monkeypatch, Session([Result(values=[agent_id])]))
    seen = _capture_es(monkeypatch, 3)
    asyncio.run(nodes.run_log_search({}, {"field": "hostname", "value": "dvwa-01"}, CTX))
    assert {"terms": {"agent_id": [str(agent_id)]}} in seen["query"]["bool"]["filter"]

    use_session(monkeypatch, Session([Result(values=[])]))
    out = asyncio.run(nodes.run_log_search({}, {"field": "hostname", "value": "ghost"}, CTX))
    assert out.data["count"] == 0


# ─── Endpoint Scan ──────────────────────────────────────────────────────────

@pytest.fixture
def queued(monkeypatch):
    calls = []

    async def queue(ctx, hostname, group_id, op, params):
        calls.append((hostname, group_id, op, params))
        return nodes.NodeResult("main", {"task_id": "t1", "hostname": hostname, "operation": op})
    monkeypatch.setattr(nodes, "_queue_agent_task", queue)
    return calls


def test_scan_operations_map_to_agent_tasks(queued):
    asyncio.run(nodes.run_scan({}, {"operation": "file_scan", "kind": "paths",
                                    "paths": "/var/www/html/dvwa/hackable/uploads\n/tmp/x.php"}, CTX))
    asyncio.run(nodes.run_scan({}, {"operation": "yara_scan", "path": "/var/www", "recursive": False}, CTX))
    asyncio.run(nodes.run_scan({}, {"operation": "memory_scan", "pid": "4242"}, CTX))
    asyncio.run(nodes.run_scan({}, {"operation": "memory_scan", "pid": ""}, CTX))
    asyncio.run(nodes.run_scan({}, {"operation": "agent_integrity", "hostname": "web-02"}, CTX))
    assert queued == [
        ("dvwa-01", "blue", "file_scan", {"kind": "paths", "paths": ["/var/www/html/dvwa/hackable/uploads", "/tmp/x.php"]}),
        ("dvwa-01", "blue", "yara_scan", {"path": "/var/www", "recursive": False}),
        ("dvwa-01", "blue", "memory_scan", {"pid": 4242}),
        ("dvwa-01", "blue", "memory_scan", {"pid": 0}),
        ("web-02", "blue", "agent_integrity", {}),
    ]


def test_scan_rejects_bad_pid_and_missing_host(queued):
    with pytest.raises(nodes.NodeError, match="pid must be a number"):
        asyncio.run(nodes.run_scan({}, {"operation": "memory_scan", "pid": "abc"}, CTX))
    with pytest.raises(nodes.NodeError, match="no hostname"):
        asyncio.run(nodes.run_scan({}, {"operation": "agent_integrity"}, {**CTX, "trigger": {"group_id": "blue"}}))


# ─── Threat Hunt ────────────────────────────────────────────────────────────

def test_hunt_creates_pending_hunt_in_group(monkeypatch, notes):
    session = Session()
    use_session(monkeypatch, session)
    out = asyncio.run(nodes.run_hunt({}, {"ioc_type": "ip", "ioc_value": "203.0.113.7"}, CTX))
    hunt = session.added[0]
    assert (hunt.ioc_type, hunt.ioc_value, hunt.status, hunt.group_id) == ("ip", "203.0.113.7", "pending", "blue")
    assert out.data["hunt_id"] == str(hunt.id) and notes
    with pytest.raises(nodes.NodeError, match="not a valid IP"):
        asyncio.run(nodes.run_hunt({}, {"ioc_type": "ip", "ioc_value": "nope"}, CTX))


# ─── Block IOC ──────────────────────────────────────────────────────────────

def test_block_ioc_malware_hash(monkeypatch, notes):
    use_session(monkeypatch, Session())
    calls = []

    async def upsert(db, rows, source, added_by=None, revive_allowed=False):
        calls.append((rows, source))
        return {"added": 1, "known": 0}
    from worker import malware_hashes
    monkeypatch.setattr(malware_hashes, "upsert", upsert)
    out = asyncio.run(nodes.run_block_ioc({}, {"operation": "malware_hash", "value": SHA.upper()}, CTX))
    assert out.data == {"operation": "malware_hash", "value": SHA, "added": True}
    assert calls[0][1] == "analyst" and calls[0][0][0]["label"] == "Web shell"
    assert calls[0][0][0]["reference"] == "SOAR run run-1"
    with pytest.raises(nodes.NodeError, match="not a SHA-256"):
        asyncio.run(nodes.run_block_ioc({}, {"operation": "malware_hash", "value": "deadbeef"}, CTX))


def test_block_ioc_prevention_rule(monkeypatch, notes):
    rule_id = uuid.uuid4()
    session = Session([Result(rule_id)])
    use_session(monkeypatch, session)
    out = asyncio.run(nodes.run_block_ioc({}, {"operation": "prevention_rule", "rule_type": "path", "action": "block",
                                               "value": "/tmp/.x/miner"}, CTX))
    params = session.executed[0][1]
    assert (params["rule_type"], params["value"], params["action"]) == ("path", "/tmp/.x/miner", "block")
    assert params["name"] == "SOAR path /tmp/.x/miner" and "ON CONFLICT (name) DO NOTHING" in str(session.executed[0][0])
    assert out.data["added"] is True and out.data["rule_id"] == str(rule_id)

    use_session(monkeypatch, Session([Result(None)]))  # same rule already there
    out = asyncio.run(nodes.run_block_ioc({}, {"operation": "prevention_rule", "rule_type": "path",
                                               "value": "/tmp/.x/miner"}, CTX))
    assert out.data["added"] is False and "already existed" in notes[-1]

    with pytest.raises(nodes.NodeError, match="absolute path"):
        asyncio.run(nodes.run_block_ioc({}, {"operation": "prevention_rule", "rule_type": "dir", "value": "tmp"}, CTX))
    with pytest.raises(nodes.NodeError, match="SHA-256"):
        asyncio.run(nodes.run_block_ioc({}, {"operation": "prevention_rule", "rule_type": "hash", "value": "x"}, CTX))


# ─── Block IOC: IP and domain ───────────────────────────────────────────────

class Rows(Result):
    """A result that is iterated (allowlist rows) or read with first()/scalar_one_or_none()."""

    def __init__(self, value=None, rows=()):
        super().__init__(value)
        self.rows = list(rows)

    def __iter__(self):
        return iter(self.rows)

    def first(self):
        return (self.value,) if self.value is not None else None


def test_block_ioc_ip_and_web_validation():
    validate(graph(("block_ioc", {"operation": "ip_block", "value": "{{ trigger.source_ip }}", "days": 7})))
    validate(graph(("block_ioc", {"operation": "web_block", "value": "{{ trigger.hostname }}"})))
    for days in (0, 366, "7", True):
        with pytest.raises(GraphError) as exc:
            validate(graph(("block_ioc", {"operation": "ip_block", "value": "x", "days": days})))
        assert any("days must be between" in e for e in exc.value.errors)


def test_block_ioc_ip_block(monkeypatch, notes):
    entry = uuid.uuid4()
    session = Session([Result(), Rows(entry)])
    use_session(monkeypatch, session)
    out = asyncio.run(nodes.run_block_ioc({}, {"operation": "ip_block", "value": "45.33.32.156", "days": 7}, CTX))
    lock, upsert = session.executed
    assert "pg_advisory_xact_lock" in str(lock[0])
    params = upsert[1]
    assert (params["cidr"], params["group"], params["source"]) == ("45.33.32.156/32", "blue", "soar")
    assert params["alert"] == uuid.UUID(CTX["trigger"]["alert_id"]) and "run-1" in params["reason"]
    assert 6 <= (params["expires"] - datetime.now(timezone.utc)).days <= 7
    assert out.data["value"] == "45.33.32.156/32" and out.data["entry_id"] == str(entry) and session.commits == 1
    assert "45.33.32.156/32" in notes[-1]
    # automation never blocks private, loopback or broad ranges
    for bad, why in (("10.0.0.5", "private"), ("127.0.0.1", "loopback"), ("8.0.0.0/8", "too broad"),
                     ("nope", "not an IP")):
        use_session(monkeypatch, Session())
        with pytest.raises(nodes.NodeError, match=why):
            asyncio.run(nodes.run_block_ioc({}, {"operation": "ip_block", "value": bad}, CTX))


def test_block_ioc_web_block_respects_allowlist(monkeypatch, notes):
    entry = uuid.uuid4()
    session = Session([Rows(rows=[]), Result(), Result(entry)])
    use_session(monkeypatch, session)
    out = asyncio.run(nodes.run_block_ioc({}, {"operation": "web_block", "value": "https://Evil.Example/x"}, CTX))
    params = session.executed[2][1]
    assert (params["domain"], params["group"]) == ("evil.example", "blue")
    assert "'soar'" in str(session.executed[2][0]) and out.data["entry_id"] == str(entry)

    allow = SimpleNamespace(domain="github.com", include_subdomains=True)
    use_session(monkeypatch, Session([Rows(rows=[allow])]))
    with pytest.raises(nodes.NodeError, match="allowlisted"):
        asyncio.run(nodes.run_block_ioc({}, {"operation": "web_block", "value": "raw.github.com"}, CTX))
