# tests/worker/test_case_grouping.py
"""Case grouping by attack family, the brute-force digest, and the
login-after-brute-force rule (sigma `after:` extension)."""
import asyncio
import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest

from worker.case_grouping import attack_family, is_failed_bruteforce, is_public_ip, raises_to_critical
from worker.graph import triage_graph

ROOT = os.path.join(os.path.dirname(__file__), "../..")


# ─── families ────────────────────────────────────────────────────

@pytest.mark.parametrize("tags,threat_type,title,family", [
    (["attack.credential_access", "attack.t1110.001"], None, "SSH Brute Force Attack", "credential_access"),
    (["attack.persistence", "attack.privilege_escalation", "attack.t1098"], None, "User Added to Privileged Group",
     "privilege_escalation"),  # the furthest tactic wins
    (["attack.initial_access", "attack.t1078", "attack.t1110"], None, "Successful Login After Brute Force",
     "initial_access"),
    ([], "scan", "whatever", "reconnaissance"),
    ([], None, "Password Spray Attack", "credential_access"),
    ([], None, "Reverse Shell Detected", "initial_access"),
    ([], None, "Cron Persistence", "persistence"),
    ([], None, "Something odd", "other"),
])
def test_attack_family(tags, threat_type, title, family):
    assert attack_family(tags, threat_type, title) == family


def test_failed_bruteforce_and_escalation_rules():
    assert is_failed_bruteforce(["attack.credential_access", "attack.t1110.001"], "SSH Brute Force Attack",
                                "credential_access")
    assert is_failed_bruteforce([], "Password Spray Attack", "credential_access")
    assert not is_failed_bruteforce(["attack.initial_access", "attack.t1110"], "Successful Login After Brute Force",
                                    "initial_access")
    assert not is_failed_bruteforce(["attack.credential_access"], "Credential Dumping (lsass)", "credential_access")
    assert raises_to_critical("persistence", {"credential_access"})
    assert raises_to_critical("execution", {"initial_access", "reconnaissance"})
    assert not raises_to_critical("reconnaissance", {"credential_access"})
    assert not raises_to_critical("persistence", {"reconnaissance"})
    assert is_public_ip("80.94.92.27") and not is_public_ip("10.0.0.5") and not is_public_ip("203.0.113.9")
    assert not is_public_ip(None) and not is_public_ip("not-an-ip")


# ─── triage routing ──────────────────────────────────────────────

class _FakeLLM:
    verdict = "create_case"
    threat_type = "brute_force"

    def __init__(self, **kwargs):
        pass

    async def ainvoke(self, messages):
        class _Reply:
            content = json.dumps({
                "verdict": _FakeLLM.verdict, "confidence": 0.9, "triage_notes": "notes",
                "mitre_techniques": [], "immediate_actions": [], "false_positive_reason": None,
                "threat_type": _FakeLLM.threat_type, "search_queries": [],
            })
        return _Reply()


@pytest.fixture(autouse=True)
def fake_llm(monkeypatch):
    _FakeLLM.verdict, _FakeLLM.threat_type = "create_case", "brute_force"
    monkeypatch.setattr(triage_graph, "NineRouterChatModel", _FakeLLM)


def _deps(calls, tags, related=None, existing=None):
    class _Enrichment:
        provider_bullets, overall_risk, triage_hints, iocs = [], 0.0, [], []

    async def noop(*a, **k):
        return None

    async def empty(*a, **k):
        return []

    async def enrich(text_blob, title):
        return _Enrichment()

    async def get_setting(key, default=""):
        return default

    async def alert_tags(alert_id):
        return tags

    async def find_case(ip, host, gid, family=None):
        calls.append(("find", family))
        return existing

    async def related_cases(ip, host, gid):
        return related or []

    async def create_case(**kwargs):
        calls.append(("create", kwargs))
        return "case-new"

    async def digest(**kwargs):
        calls.append(("digest", kwargs))
        return "case-digest"

    async def add_note(*a):
        calls.append(("note", a[0]))

    return {
        "enrich": enrich, "escalate_severity": lambda base, risk: base,
        "suggest_mitre": lambda text: [], "retrieve_similar_cases": empty,
        "retrieve_sop_context": empty, "retrieve_feedback_context": empty,
        "enqueue_hunt": noop, "get_setting": get_setting, "set_alert_verdict": noop,
        "write_alert_note": noop, "tag_alert_with_mitre": noop, "run_soar_playbooks": noop,
        "update_alert_status": noop, "run_searches": noop, "find_existing_open_case": find_case,
        "add_note_to_existing_case": add_note, "create_case_from_verdict": create_case,
        "analyze_campaign": noop, "check_fleet_spread": noop, "dispatch_case_webhooks": noop,
        "alert_tags": alert_tags, "related_open_cases": related_cases, "add_to_bruteforce_digest": digest,
    }


def _run(deps, title, ip, host="web01", severity="high"):
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    state = {"alert_id": "11111111-1111-1111-1111-111111111111", "title": title, "severity": severity,
             "source_ip": ip, "hostname": host, "decoded_fields": {}, "group_id": "default"}
    return asyncio.run(graph.ainvoke(state, {"configurable": {"thread_id": f"t-{title}-{ip}"}}))


BF_TAGS = ["attack.credential_access", "attack.t1110.001"]


def test_public_bruteforce_goes_to_the_daily_digest():
    calls = []
    final = _run(_deps(calls, BF_TAGS), "SSH Brute Force Attack [5x in 300s from 80.94.92.27]", "80.94.92.27")
    assert final["case_id"] == "case-digest"
    assert [c[0] for c in calls] == ["digest"]


def test_internal_bruteforce_and_escalations_still_get_cases():
    calls = []
    _run(_deps(calls, BF_TAGS), "SSH Brute Force Attack", "10.0.0.7")  # lateral, worth a case
    assert ("find", "credential_access") in calls and any(c[0] == "create" for c in calls)
    calls = []
    _FakeLLM.verdict = "escalate"
    _run(_deps(calls, BF_TAGS), "SSH Brute Force Attack", "80.94.92.27")
    assert not any(c[0] == "digest" for c in calls) and any(c[0] == "create" for c in calls)


def test_a_new_family_on_the_same_host_gets_its_own_linked_case():
    calls = []
    _FakeLLM.threat_type = "privilege_escalation"
    related = [{"case_id": "case-bf", "family": "credential_access", "title": "[AI] SSH Brute Force"}]
    _run(_deps(calls, ["attack.persistence", "attack.privilege_escalation"], related=related),
         "User Added to Privileged Linux Group", "10.0.0.7")
    assert ("find", "privilege_escalation") in calls
    created = next(c[1] for c in calls if c[0] == "create")
    assert created["family"] == "privilege_escalation" and created["related"] == related
    assert created["hostname"] == "web01"


def test_same_family_joins_the_open_case():
    calls = []
    final = _run(_deps(calls, ["attack.execution"], existing="case-exec"), "Suspicious PowerShell Script Block",
                 "10.0.0.7")
    assert final["case_id"] == "case-exec" and ("note", "case-exec") in calls
    assert not any(c[0] == "create" for c in calls)


# ─── the rule ────────────────────────────────────────────────────

def _engines():
    import yaml
    from worker.decoder_engine import DecoderEngine
    from worker.sigma_engine import SigmaEngine
    decs = sorted((open(p).read() for p in glob.glob(os.path.join(ROOT, "decoders/*.yaml"))),
                  key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decs)
    sig = SigmaEngine()
    sig.load_from_yaml_list([open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, "rules/*.yaml")))])
    assert not sig.load_errors, sig.load_errors
    return dec, sig


def _feed(dec, sig, line):
    ev = {**dec.decode("linux_auth", line), "raw_message": line, "log_type": "linux_auth", "hostname": "web01"}
    return [m["title"] for m in asyncio.run(sig.evaluate(ev))]


H = "Oct 19 10:00:00 web01 "


def test_login_after_brute_force():
    dec, sig = _engines()
    fail = H + "sshd[1]: Failed password for root from 80.94.92.27 port 2222 ssh2"
    ok = H + "sshd[1]: Accepted password for root from 80.94.92.27 port 2222 ssh2"
    for _ in range(4):
        _feed(dec, sig, fail)
    assert not any("After Brute Force" in t for t in _feed(dec, sig, ok))  # only 4 failures so far

    _feed(dec, sig, fail)  # the 5th
    titles = _feed(dec, sig, ok)
    hit = [t for t in titles if t.startswith("Successful Login After Brute Force")]
    assert hit == ["Successful Login After Brute Force [after 5 earlier events in 3600s from 80.94.92.27]"]
    # the sequence is consumed: the next success alone doesn't fire again
    assert not any("After Brute Force" in t for t in _feed(dec, sig, ok))
    # and failures from another source don't count for this one
    for _ in range(5):
        _feed(dec, sig, fail.replace("80.94.92.27", "45.1.2.3"))
    assert not any("After Brute Force" in t for t in _feed(dec, sig, ok))


def test_after_extension_validation():
    from worker.sigma_engine import SigmaEngine
    sig = SigmaEngine()
    sig.load_from_yaml_list([
        "title: a\ndetection:\n  s:\n    x: 1\n  condition: s\nafter:\n  count: 2\n",
        "title: b\ndetection:\n  s:\n    x: 1\n  condition: s\nafter:\n  detection:\n    f:\n      y: 1\n"
        "    condition: f\n  count: zero\n",
    ])
    errors = " | ".join(e for _, e in sig.load_errors)
    assert "'after' needs a detection block" in errors and "'after.count' must be a number" in errors
