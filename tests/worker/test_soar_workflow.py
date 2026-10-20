# tests/worker/test_soar_workflow.py
"""SOAR workflow building blocks without a database: templates, curl parsing,
graph validation, legacy conversion, conditions, the outbound URL guard and
the HTTP Request node."""
import asyncio
import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import httpx  # noqa: E402
import pytest  # noqa: E402

from worker.soar import nodes  # noqa: E402
from worker.soar.conditions import matches  # noqa: E402
from worker.soar.curl import CurlParseError, parse_curl  # noqa: E402
from worker.soar.graph import GraphError, from_legacy, trigger_event, validate  # noqa: E402
from worker.soar.template import lookup, references, render  # noqa: E402

CTX = {
    "trigger": {"source_ip": "203.0.113.7", "severity": "high", "tags": ["a", "b"], "ai_confidence": 0.9},
    "steps": {"http_1": {"status": 200, "body": {"data": {"score": 87, "items": [{"ip": "1.1.1.1"}]}}}},
    "secrets": {"VT": "s3cret"},
}


# ─── templates ──────────────────────────────────────────────────────────────

def test_lookup_paths_and_bare_trigger_fields():
    assert lookup(CTX, "steps.http_1.body.data.score") == 87
    assert lookup(CTX, "steps.http_1.body.data.items[0].ip") == "1.1.1.1"
    assert lookup(CTX, "source_ip") == "203.0.113.7"          # bare → trigger
    assert lookup(CTX, "steps.http_1.body.nope", "dflt") == "dflt"
    assert lookup(CTX, "trigger.tags[5]") is None


def test_render_keeps_type_for_whole_token_and_interpolates_text():
    assert render("{{ steps.http_1.body.data.score }}", CTX) == 87
    assert render("{{ steps.http_1.body.data }}", CTX) == {"score": 87, "items": [{"ip": "1.1.1.1"}]}
    assert render("ip={{ source_ip }} sev={{trigger.severity}}", CTX) == "ip=203.0.113.7 sev=high"
    assert render({"h": {"x-apikey": "{{ secrets.VT }}"}, "l": ["{{ trigger.tags }}"]}, CTX) == \
        {"h": {"x-apikey": "s3cret"}, "l": [["a", "b"]]}
    assert render("missing={{ steps.zzz.a }}", CTX) == "missing="


def test_render_never_evaluates_code():
    for evil in ("{{ __import__('os').system('id') }}", "{{ ''.__class__ }}", "{{ 1+1 }}"):
        out = render(evil, CTX)
        assert out in (None, "") or "os" not in str(out)
    assert references("a {{ steps.x.y }} b {{ trigger.z }}") == ["steps.x.y", "trigger.z"]


# ─── curl ───────────────────────────────────────────────────────────────────

def test_parse_curl_json_post_with_headers_and_auth():
    cmd = """curl -s -X POST 'https://api.example.com/v1/block?dry=1' \\
      -H 'Content-Type: application/json' -H "X-Api-Key: abc" -u admin:pw \\
      -d '{"ip": "{{ trigger.source_ip }}", "ttl": 3600}' -m 20"""
    out = parse_curl(cmd)
    p = out["params"]
    assert p["method"] == "POST" and p["url"] == "https://api.example.com/v1/block"
    assert p["query"] == {"dry": "1"}
    assert p["headers"]["X-Api-Key"] == "abc"
    assert p["headers"]["Authorization"].startswith("Basic ")
    assert p["body_type"] == "json" and p["body"] == {"ip": "{{ trigger.source_ip }}", "ttl": 3600}
    assert p["timeout"] == 20
    assert "-s" in out["ignored"]


def test_parse_curl_form_get_and_defaults():
    p = parse_curl("curl https://x.test/q -d a=1 -d b=two")["params"]
    assert p["method"] == "POST" and p["body_type"] == "form" and p["body"] == {"a": "1", "b": "two"}
    p = parse_curl("curl -G https://x.test/q --data-urlencode 'q=a b'")["params"]
    assert p["method"] == "GET" and p["query"] == {"q": "a b"} and p["body_type"] == "none"
    p = parse_curl("curl --json '{\"a\":1}' x.test/api")["params"]
    assert p["url"] == "http://x.test/api" and p["body"] == {"a": 1} and p["method"] == "POST"


@pytest.mark.parametrize("cmd", ["wget http://x", "curl", "curl -d @/etc/passwd http://x", "curl 'unterminated"])
def test_parse_curl_rejects(cmd):
    with pytest.raises(CurlParseError):
        parse_curl(cmd)


# ─── graph ──────────────────────────────────────────────────────────────────

def _graph(**over):
    g = {
        "nodes": [
            {"id": "t", "type": "trigger", "params": {"event": "alert.triaged",
                                                       "conditions": [{"field": "severity", "operator": "eq", "value": "high"}]}},
            {"id": "http_1", "type": "http", "params": {"method": "GET", "url": "https://ti.example/{{ trigger.source_ip }}",
                                                         "extract": {"score": "body.data.score"}}},
            {"id": "check", "type": "if", "params": {"conditions": [
                {"field": "steps.http_1.data.score", "operator": "gte", "value": 80}]}},
            {"id": "block", "type": "response", "params": {"operation": "block_ip"}},
            {"id": "note", "type": "case", "params": {"operation": "add_note", "content": "score {{ steps.http_1.data.score }}"}},
        ],
        "edges": [
            {"from": "t", "output": "main", "to": "http_1"},
            {"from": "http_1", "output": "main", "to": "check"},
            {"from": "check", "output": "true", "to": "block"},
            {"from": "check", "output": "false", "to": "note"},
        ],
    }
    g.update(over)
    return g


def test_validate_accepts_branching_graph():
    g = validate(_graph())
    assert trigger_event(g) == "alert.triaged"
    assert {n["id"] for n in g["nodes"]} == {"t", "http_1", "check", "block", "note"}


def _errors(graph):
    with pytest.raises(GraphError) as exc:
        validate(graph)
    return " | ".join(exc.value.errors)


def test_validate_rejects_bad_graphs():
    g = _graph()
    assert "loop" in _errors({**g, "edges": g["edges"] + [{"from": "block", "output": "main", "to": "http_1"}]})
    assert "exactly one Trigger" in _errors({**g, "nodes": g["nodes"][1:], "edges": g["edges"][1:]})
    assert "has no output" in _errors({**g, "edges": g["edges"] + [{"from": "check", "output": "maybe", "to": "note"}]})
    bad = [dict(n) for n in g["nodes"]]
    bad[3] = {"id": "block", "type": "response", "params": {"operation": "format_disk"}}
    assert "operation must be" in _errors({**g, "nodes": bad})
    late = [dict(n) for n in g["nodes"]]
    late[1] = {**late[1], "params": {**late[1]["params"], "url": "https://x/{{ steps.block.task_id }}"}}
    assert "does not run before it" in _errors({**g, "nodes": late})
    assert "unknown type" in _errors({**g, "nodes": g["nodes"] + [{"id": "x", "type": "code", "params": {}}]})
    assert "bad node id" in _errors({**g, "nodes": g["nodes"] + [{"id": "Bad Id", "type": "if", "params": {}}]})


def test_legacy_playbook_converts_to_a_linear_workflow():
    g = validate(from_legacy(
        {"match": "all", "conditions": [{"field": "ai_verdict", "operator": "eq", "value": "escalate"}]},
        [{"action_type": "block_ip", "order_index": 1, "params": {"duration_seconds": 86400}},
         {"action_type": "create_case", "order_index": 0, "params": {"title_template": "SOAR: {alert_title}"}},
         {"action_type": "unknown_thing", "order_index": 2, "params": {}}],
    ))
    assert trigger_event(g) == "alert.triaged"   # looked at the AI verdict → runs once, after triage
    types = [n["type"] for n in g["nodes"]]
    assert types == ["trigger", "case", "response"]
    assert g["nodes"][1]["params"]["title"] == "SOAR: {{ trigger.rule_title }}"
    assert all(n["continue_on_error"] for n in g["nodes"][1:])
    assert [(e["from"], e["to"]) for e in g["edges"]] == [("trigger", "step_1"), ("step_1", "step_2")]
    assert trigger_event(validate(from_legacy({}, []))) == "alert.created"


# ─── conditions ─────────────────────────────────────────────────────────────

def test_conditions_on_step_outputs_and_new_operators():
    def m(field, op, value=None):
        return matches({"conditions": [{"field": field, "operator": op, "value": value}]}, CTX)
    assert m("steps.http_1.body.data.score", "gt", 80)
    assert not m("steps.http_1.body.data.score", "lt", "{{ steps.http_1.body.data.score }}")
    assert m("steps.http_1.status", "in", "200, 201")
    assert m("trigger.severity", "regex", "^hi")
    assert not m("trigger.severity", "regex", "([")       # bad regex is just false
    assert m("steps.http_1.body.nothing", "is_null")


# ─── outbound URL guard ─────────────────────────────────────────────────────

def _resolve_to(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 1, 6, "", (ip, 443))])


def _check(url, allow=""):
    return asyncio.run(nodes.check_target(url, allow))


def test_check_target(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_WEBHOOK_TARGETS", raising=False)
    _resolve_to(monkeypatch, "93.184.216.34")
    assert _check("https://api.example.com/x") is None
    assert "scheme" in _check("file:///etc/passwd")
    _resolve_to(monkeypatch, "10.0.5.20")
    assert "soar_http_allowlist" in _check("https://fw.corp.local/api")
    assert _check("https://fw.corp.local/api", "fw.corp.local") is None
    assert _check("https://fw.corp.local/api", "10.0.5.0/24") is None
    _resolve_to(monkeypatch, "169.254.169.254")
    assert "never allowed" in _check("http://metadata/latest", "169.254.0.0/16")
    _resolve_to(monkeypatch, "127.0.0.1")
    assert "never allowed" in _check("http://localhost:6379", "localhost")


# ─── HTTP Request node ──────────────────────────────────────────────────────

_REAL_CLIENT = httpx.AsyncClient


def _http(monkeypatch, handler, params):
    async def allow(url, allowlist=""):
        return None
    async def setting(key, default=""):
        return ""
    monkeypatch.setattr(nodes, "check_target", allow)
    monkeypatch.setattr("worker.settings_cache.get_setting", setting)
    monkeypatch.setattr(nodes.httpx, "AsyncClient",
                        lambda **kw: _REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    return asyncio.run(nodes.run_http({"id": "h"}, params, CTX))


def test_http_node_sends_request_and_extracts(monkeypatch):
    seen = {}

    def handler(request):
        seen.update(method=request.method, url=str(request.url), key=request.headers.get("x-api-key"),
                    body=request.content)
        return httpx.Response(200, json={"data": {"score": 91, "tags": ["c2"]}})

    res = _http(monkeypatch, handler, {"method": "POST", "url": "https://ti.example/check", "query": {"v": "2"},
                                       "headers": {"X-Api-Key": "k"}, "body_type": "json", "body": {"ip": "1.2.3.4"},
                                       "extract": {"score": "body.data.score", "first_tag": "body.data.tags[0]"}})
    assert res.output == "main"
    assert seen["method"] == "POST" and seen["url"] == "https://ti.example/check?v=2" and seen["key"] == "k"
    assert b'"ip"' in seen["body"]
    assert res.data["status"] == 200 and res.data["data"] == {"score": 91, "first_tag": "c2"}


def test_http_node_error_status_goes_to_error_with_data(monkeypatch):
    with pytest.raises(nodes.NodeError) as exc:
        _http(monkeypatch, lambda r: httpx.Response(503, text="busy"), {"url": "https://x.example"})
    assert exc.value.data["status"] == 503 and exc.value.data["body"] == "busy"
    res = _http(monkeypatch, lambda r: httpx.Response(404, json={"m": "nf"}),
                {"url": "https://x.example", "fail_on_status": False})
    assert res.output == "main" and res.data["ok"] is False


def test_http_node_caps_body_and_does_not_follow_redirects(monkeypatch):
    big = b"x" * (nodes.HTTP_MAX_BYTES + 5000)
    res = _http(monkeypatch, lambda r: httpx.Response(200, content=big), {"url": "https://x.example"})
    assert res.data["truncated"] is True and len(res.data["body"]) == nodes.HTTP_MAX_BYTES
    res = _http(monkeypatch, lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/"}),
                {"url": "https://x.example"})
    assert res.data["status"] == 302
