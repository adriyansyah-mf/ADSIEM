# tests/worker/test_ai_retry.py
"""AI triage when the LLM is rate-limited or down: the alert is queued again
with backoff instead of getting a canned verdict. Critical/high still
escalate at once and only get the AI's view added later; lower severities
stay open until the AI answers or the retries are used up."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import ai_retry  # noqa: E402
from worker.config import AI_ANALYSIS_QUEUE  # noqa: E402
from worker.graph import triage_graph  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.z, self.sets, self.lists = {}, {}, {}

    async def zadd(self, key, mapping):
        self.z.setdefault(key, {}).update(mapping)

    async def zrangebyscore(self, key, lo, hi, start=0, num=None):
        items = sorted((s, m) for m, s in self.z.get(key, {}).items() if lo <= s <= hi)
        return [m for _, m in items][start:start + num if num else None]

    async def zrem(self, key, member):
        return 1 if self.z.get(key, {}).pop(member, None) is not None else 0

    async def sadd(self, key, v):
        self.sets.setdefault(key, set()).add(v)

    async def srem(self, key, v):
        self.sets.get(key, set()).discard(v)

    async def sismember(self, key, v):
        return v in self.sets.get(key, set())

    async def expire(self, key, ttl):
        pass

    async def rpush(self, key, v):
        self.lists.setdefault(key, []).append(v)


async def test_schedule_then_requeue_when_due():
    r = FakeRedis()
    payload = {"alert_id": "a1", "title": "t", "severity": "medium", "group_id": "default"}
    delay = await ai_retry.schedule(r, payload, 0, now=1000)
    assert 120 <= delay <= 144  # 2 min + up to 20% jitter
    assert await ai_retry.is_pending(r, "a1")
    assert await ai_retry.requeue_due(r, now=1000 + 60) == 0  # not yet
    assert await ai_retry.requeue_due(r, now=1000 + 200) == 1
    item = json.loads(r.lists[AI_ANALYSIS_QUEUE][0])
    assert item["alert_id"] == "a1" and item["attempt"] == 1
    assert not await ai_retry.is_pending(r, "a1")
    assert await ai_retry.requeue_due(r, now=1000 + 200) == 0  # moved once


async def test_backoff_grows_and_ends():
    delays = [ai_retry.backoff(a) for a in range(ai_retry.MAX_ATTEMPTS)]
    assert all(b > a for a, b in zip(delays, delays[1:]))
    assert ai_retry.backoff(ai_retry.MAX_ATTEMPTS) is None
    assert await ai_retry.schedule(FakeRedis(), {"alert_id": "a"}, ai_retry.MAX_ATTEMPTS) is None


# --- the triage graph with an LLM that is rate-limited

class _RateLimitedLLM:
    def __init__(self, **kwargs):
        pass

    async def ainvoke(self, messages):
        raise RuntimeError("9router chat failed after 4 attempts: rate limited (429)")


class _OkLLM:
    def __init__(self, **kwargs):
        pass

    async def ainvoke(self, messages):
        class _Reply:
            content = json.dumps({"verdict": "false_positive", "confidence": 0.9, "triage_notes": "benign scanner",
                                  "mitre_techniques": [], "immediate_actions": [], "search_queries": []})
        return _Reply()


def _harness(retry_delay):
    calls = {"status": [], "notes": [], "cases": 0, "soar": 0, "retries": []}

    class _Enrichment:
        provider_bullets, overall_risk, triage_hints, iocs = [], 0.0, [], []

    async def noop(*a, **k):
        return None

    async def enrich(text_blob, title):
        return _Enrichment()

    async def get_setting(key, default=""):
        return default

    def returns(value):
        async def f(*a, **k):
            return value
        return f

    async def status(alert_id, s):
        calls["status"].append(s)

    async def note(alert_id, text):
        calls["notes"].append(text)

    async def create_case(**kw):
        calls["cases"] += 1
        return "case-1"

    async def soar(**kw):
        calls["soar"] += 1

    async def retry(state, attempt, annotate_only):
        calls["retries"].append((attempt, annotate_only))
        return retry_delay

    deps = {
        "enrich": enrich, "escalate_severity": lambda base, risk: base, "suggest_mitre": lambda text: [],
        "retrieve_similar_cases": returns([]), "retrieve_sop_context": returns([]),
        "retrieve_feedback_context": returns([]),
        "enqueue_hunt": noop, "get_setting": get_setting, "set_alert_verdict": noop, "write_alert_note": note,
        "tag_alert_with_mitre": noop, "run_soar_playbooks": soar, "update_alert_status": status, "run_searches": noop,
        "find_campaign_case": returns((None, [])), "join_campaign_case": noop, "create_case_from_verdict": create_case,
        "analyze_campaign": noop, "check_fleet_spread": noop, "dispatch_case_webhooks": noop,
        "schedule_ai_retry": retry,
    }
    return deps, calls


def _state(severity, **extra):
    return dict({"alert_id": "33333333-3333-3333-3333-333333333333", "title": "Port scan", "severity": severity,
                 "source_ip": "203.0.113.9", "hostname": "web01", "decoded_fields": {}, "group_id": "default"},
                **extra)


async def _run(monkeypatch, llm, state, retry_delay, thread):
    monkeypatch.setattr(triage_graph, "NineRouterChatModel", llm)
    deps, calls = _harness(retry_delay)
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    await graph.ainvoke(state, {"configurable": {"thread_id": thread}})
    return calls


async def test_rate_limited_medium_alert_stays_open_and_is_retried(monkeypatch):
    calls = await _run(monkeypatch, _RateLimitedLLM, _state("medium"), 130.0, "retry-1")
    assert calls["retries"] == [(0, False)]
    assert calls["status"] == []  # not acknowledged: it waits for the AI
    assert calls["cases"] == 0 and calls["soar"] == 0
    assert len(calls["notes"]) == 1 and "PENDING" in calls["notes"][0]


async def test_rate_limited_critical_alert_escalates_now_and_retries_for_the_note(monkeypatch):
    calls = await _run(monkeypatch, _RateLimitedLLM, _state("critical"), 130.0, "retry-2")
    assert calls["retries"] == [(0, True)]  # the retry only annotates
    assert calls["cases"] == 1  # L2 gets it at once
    assert any("retried in about 2 min" in n for n in calls["notes"])


async def test_retry_after_escalation_only_adds_the_ai_view(monkeypatch):
    calls = await _run(monkeypatch, _OkLLM, _state("critical", attempt=1, annotate_only=True), 130.0, "retry-3")
    assert calls["cases"] == 0 and calls["soar"] == 0 and calls["status"] == []  # no second case, no auto-close
    assert len(calls["notes"]) == 1 and "delayed" in calls["notes"][0] and "L2 decides" in calls["notes"][0]


async def test_retries_used_up_falls_back_for_good(monkeypatch):
    calls = await _run(monkeypatch, _RateLimitedLLM, _state("medium", attempt=5), None, "retry-4")
    assert calls["status"] == ["acknowledged"]
    assert any("gave up after 6 attempts" in n for n in calls["notes"])


async def test_annotate_only_retries_used_up_says_so(monkeypatch):
    calls = await _run(monkeypatch, _RateLimitedLLM, _state("critical", attempt=5, annotate_only=True), None,
                       "retry-5")
    assert calls["cases"] == 0 and calls["status"] == []
    assert len(calls["notes"]) == 1 and "GAVE UP" in calls["notes"][0]


async def test_without_a_scheduler_it_falls_back_as_before(monkeypatch):
    monkeypatch.setattr(triage_graph, "NineRouterChatModel", _RateLimitedLLM)
    deps, calls = _harness(None)
    del deps["schedule_ai_retry"]
    graph = triage_graph.build_triage_graph(base_url="x", api_key="k", model="m", deps=deps)
    await graph.ainvoke(_state("high"), {"configurable": {"thread_id": "retry-6"}})
    assert calls["cases"] == 1
