"""worker/retro_hunt.py against a fake Elasticsearch: an IOC hunt finds the
indicator in any stored line of the group and window, groups the sightings
by host and alerts once per host; a rule hunt pages through the events its
logsource covers and reports what the rule would have caught."""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from worker import retro_hunt as rh

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
AGENT = str(uuid.uuid4())
_LOOP = asyncio.new_event_loop()


def run(coro):
    return _LOOP.run_until_complete(coro)


def test_ioc_query_finds_the_value_anywhere_in_the_group_and_window():
    q = rh.ioc_query("ip", "45.129.56.138", "blue", 30, now=NOW)["bool"]
    assert {"match_phrase": {"raw_message": "45.129.56.138"}} in q["should"]
    assert {"term": {"source_ip": "45.129.56.138"}} in q["should"] and q["minimum_should_match"] == 1
    assert {"term": {"group_id": "blue"}} in q["filter"]
    assert q["filter"][0]["range"]["created_at"]["gte"].startswith("2026-10-16")
    every_group = rh.ioc_query("domain", "evil.example", "*", 7, now=NOW)["bool"]
    assert not any("group_id" in json.dumps(f) for f in every_group["filter"])
    assert every_group["should"] == [{"match_phrase": {"raw_message": "evil.example"}}]


@pytest.mark.parametrize("ioc_type,value,expect", [
    ("ip", " 45.129.56.138 ", "45.129.56.138"), ("ip", "2001:db8::1", "2001:db8::1"), ("ip", "evil", None),
    ("hash", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"), ("hash", "xyz", None),
    ("domain", "Evil.Example.", "evil.example"), ("domain", "nodot", None), ("url", "http://x/a.sh", "http://x/a.sh"),
    ("text", "ab", None), ("port", "22", None),
])
def test_ioc_values_are_validated(ioc_type, value, expect):
    assert rh.valid_ioc(ioc_type, value) == expect


def test_a_rules_logsource_becomes_its_log_types():
    assert rh.log_type_patterns({"product": "suricata", "service": "modbus"}) == ["suricata"]
    assert "linux_process_exec" in rh.log_type_patterns({"product": "linux", "category": "process_creation"})
    assert rh.log_type_patterns({"product": "acme", "service": "vpn"}) == ["acme_vpn"]
    assert rh.log_type_patterns(None) is None
    q = rh.rule_query(["linux_*", "syslog"], "*", 7, now=NOW)["bool"]["filter"]
    assert {"wildcard": {"log_type": "linux_*"}} in q[1]["bool"]["should"]


class FakeES:
    def __init__(self, ioc_response=None, pages=None):
        self.ioc_response, self.pages, self.bodies = ioc_response, list(pages or []), []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        self.bodies.append((request.method, path, body))
        if path == "/logs/_search":
            return httpx.Response(200, json=self.ioc_response)
        if path == "/logs/_pit":
            return httpx.Response(200, json={"id": "pit-1"})
        if path == "/_search":
            return httpx.Response(200, json={"pit_id": "pit-1", "hits": {"hits": self.pages.pop(0) if self.pages else []}})
        if path == "/_pit" and request.method == "DELETE":
            return httpx.Response(200, json={"succeeded": True})
        raise AssertionError(f"unexpected {request.method} {path}")


def bucket(key, count, lines):
    return {"key": key, "doc_count": count,
            "first": {"value_as_string": "2026-11-13T19:40:08.000Z"}, "last": {"value_as_string": "2026-11-13T19:41:30.000Z"},
            "group": {"buckets": [{"key": "default", "doc_count": count}]},
            "samples": {"hits": {"hits": [{"_id": str(uuid.uuid4()), "_source": {"raw_message": l, "log_type": "nginx_access",
                                                                                "created_at": "2026-11-13T19:41:30Z"}} for l in lines]}}}


def test_ioc_hunt_groups_by_host_and_alerts_once_per_host(monkeypatch):
    es = FakeES(ioc_response={"hits": {"total": {"value": 14}}, "aggregations": {"hosts": {"buckets": [
        bucket(AGENT, 12, ['45.129.56.138 - - "POST /p.php HTTP/1.1" 200']),
        bucket("_none_", 2, ["Nov 14 fw01 kernel: DROP SRC=45.129.56.138"]),
    ]}}})
    alerts = []

    async def hostnames(ids):
        return {AGENT: "otakunesia"}

    async def create_alert(**kw):
        alerts.append(kw)
        return uuid.uuid4()
    monkeypatch.setattr(rh, "_hostnames", hostnames)
    import worker.alert_manager as am
    monkeypatch.setattr(am, "create_alert", create_alert)
    hunt = SimpleNamespace(kind="ioc", ioc_type="ip", ioc_value="45.129.56.138", group_id="default", days=30,
                           trigger="ip_block", create_alerts=True)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(es.handler), base_url="http://es") as c:
            return await rh.run_ioc(c, hunt)
    out = run(go())
    assert out["matched"] == 14 and out["hosts"] == 2 and out["alerts_created"] == 2
    hosts = {h["hostname"]: h for h in out["results"]["hosts"]}
    assert hosts["otakunesia"]["count"] == 12 and hosts["otakunesia"]["first_seen"].startswith("2026-11-13T19:40")
    assert "syslog / agentless" in hosts and "p.php" in hosts["otakunesia"]["samples"][0]["line"]
    titles = {a["rule_match"]["title"] for a in alerts}
    assert titles == {"Retro-hunt: IP 45.129.56.138 Seen In Past Logs"}
    assert {a["hostname"] for a in alerts} == {"otakunesia", "syslog / agentless"}
    assert all(a["source_ip"] == "45.129.56.138" and a["rule_match"]["level"] == "high" for a in alerts)
    agg = es.bodies[0][2]["aggs"]["hosts"]
    assert agg["terms"]["field"] == "agent_id" and agg["aggs"]["samples"]["top_hits"]["size"] == rh.SAMPLES_PER_HOST


def test_an_ioc_hunt_without_alerts_only_reports(monkeypatch):
    es = FakeES(ioc_response={"hits": {"total": {"value": 0}}, "aggregations": {"hosts": {"buckets": []}}})

    async def hostnames(ids):
        return {}
    monkeypatch.setattr(rh, "_hostnames", hostnames)
    hunt = SimpleNamespace(kind="ioc", ioc_type="domain", ioc_value="evil.example", group_id="*", days=7,
                           trigger="manual", create_alerts=True)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(es.handler), base_url="http://es") as c:
            return await rh.run_ioc(c, hunt)
    out = run(go())
    assert out == {"matched": 0, "hosts": 0, "alerts_created": 0, "truncated": False, "results": {"hosts": []}}


RULE = """title: Webshell Test Rule
id: rule-test-webshell
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    Image|endswith: /whoami
    User: '33'
  condition: sel
level: high
"""


def doc(image, user, n):
    line = f'Image="{image}" CommandLine="{image.rsplit("/", 1)[1]}" PID={n} PPID=1 User={user} ParentImage="/bin/sh"'
    return {"_id": str(uuid.uuid4()), "sort": [n], "_source": {
        "raw_message": line, "log_type": "linux_process_exec", "group_id": "default", "agent_id": AGENT,
        "created_at": f"2026-11-13T19:4{n % 10}:00Z",
        "decoded_fields": {"Image": image, "User": user, "ParentImage": "/bin/sh"}}}


def test_rule_hunt_pages_through_events_and_reports_matches(monkeypatch):
    page1 = [doc("/usr/bin/id", "33", i) for i in range(rh.RULE_PAGE - 1)] + [doc("/usr/bin/whoami", "33", 999)]
    page2 = [doc("/usr/bin/whoami", "0", 1000), doc("/usr/bin/whoami", "33", 1001)]
    es = FakeES(pages=[page1, page2])
    rule = SimpleNamespace(id=uuid.uuid4(), title="Webshell Test Rule", content=RULE, level="high",
                           tags=["attack.t1505.003"], mitre_tags=["attack.t1505.003"])

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, model, key):
            return rule

    async def hostnames(ids):
        return {AGENT: "otakunesia"}
    monkeypatch.setattr(rh, "AsyncSessionLocal", Session)
    monkeypatch.setattr(rh, "_hostnames", hostnames)
    hunt = SimpleNamespace(kind="rule", rule_id=rule.id, group_id="default", days=7, create_alerts=False)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(es.handler), base_url="http://es") as c:
            return await rh.run_rule(c, hunt)
    out = run(go())
    assert out["scanned"] == rh.RULE_PAGE + 2 and out["matched"] == 2 and out["alerts_created"] == 0
    assert out["results"]["host_names"] == ["otakunesia"] and not out["truncated"]
    searches = [b for m, p, b in es.bodies if p == "/_search"]
    assert "search_after" not in searches[0] and searches[1]["search_after"] == [999]
    assert {"wildcard": {"log_type": "linux_process_exec"}} in searches[0]["query"]["bool"]["filter"][2]["bool"]["should"]
    assert ("DELETE", "/_pit", {"id": "pit-1"}) in es.bodies  # the point in time is released


def test_a_correlation_rule_is_refused(monkeypatch):
    rule = SimpleNamespace(id=uuid.uuid4(), title="Burst", level="high", tags=[], mitre_tags=[], content=(
        "title: Burst\ncorrelation:\n  type: event_count\n  rules: [x]\n  timespan: 5m\n  condition:\n    gte: 3\n"))

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, model, key):
            return rule
    monkeypatch.setattr(rh, "AsyncSessionLocal", Session)
    hunt = SimpleNamespace(kind="rule", rule_id=rule.id, group_id="*", days=7, create_alerts=False)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(FakeES().handler), base_url="http://es") as c:
            return await rh.run_rule(c, hunt)
    with pytest.raises(ValueError):
        run(go())
