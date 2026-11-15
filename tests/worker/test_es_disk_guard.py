"""worker/es_disk_guard.py against a fake Elasticsearch: when the disk is at or
above the threshold it deletes the oldest days of logs (as polled tasks) and
expunges them, stops once below, never touches the protected newest days,
and its health events raise the siem rules."""
import asyncio
import glob
import json
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import yaml

from worker import es_disk_guard as guard_mod
from worker.agent_health import health_line
from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
ROOT = os.path.join(os.path.dirname(__file__), "../..")
_LOOP = asyncio.new_event_loop()


class FakeES:
    """Logs per day; disk usage is a base plus 2% per day still on disk. A
    delete only marks documents: the disk is freed by forcemerge."""

    def __init__(self, days: int, base: float = 70.0, per_day: float = 2.0, other: float = 0.0):
        self.on_disk = {(NOW - timedelta(days=d)).date(): 1000 for d in range(days)}
        self.live = dict(self.on_disk)
        self.base, self.per_day, self.other = base, per_day, other
        self.tasks: dict[str, dict] = {}
        self.calls: list[str] = []

    def percent(self) -> float:
        return self.base + self.other + self.per_day * len(self.on_disk)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, params = request.url.path, dict(request.url.params)
        self.calls.append(f"{request.method} {path}")
        if path == "/_cat/allocation":
            return httpx.Response(200, json=[{"node": "es1", "disk.percent": str(round(self.percent()))},
                                             {"node": "UNASSIGNED", "disk.percent": None}])
        if path == "/logs/_search":
            if not self.live:
                return httpx.Response(200, json={"aggregations": {"oldest": {"value": None}}})
            oldest = min(self.live)
            ms = datetime(oldest.year, oldest.month, oldest.day, 6, tzinfo=timezone.utc).timestamp() * 1000
            return httpx.Response(200, json={"aggregations": {"oldest": {"value": ms}}})
        if path == "/logs/_delete_by_query":
            assert params.get("wait_for_completion") == "false" and params.get("conflicts") == "proceed"
            cutoff = datetime.fromisoformat(json.loads(request.content)["query"]["range"]["created_at"]["lt"])
            gone = [d for d in self.live if d < cutoff.date()]
            deleted = sum(self.live.pop(d) for d in gone)
            return self._task({"deleted": deleted})
        if path == "/logs/_forcemerge":
            assert params.get("only_expunge_deletes") == "true"
            self.on_disk = dict(self.live)
            return self._task({})
        if path.startswith("/_tasks/"):
            task = self.tasks[path.rsplit("/", 1)[1]]
            task["polls"] += 1
            done = task["polls"] >= 2  # running on the first poll
            return httpx.Response(200, json={"completed": done, "response": task["response"] if done else None})
        raise AssertionError(f"unexpected call {request.method} {path}")

    def _task(self, response: dict) -> httpx.Response:
        tid = f"node:{len(self.tasks) + 1}"
        self.tasks[tid] = {"response": response, "polls": 0}
        return httpx.Response(200, json={"task": tid})


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(guard_mod, "TASK_POLL_SECONDS", 0.0)


def run(es: FakeES, threshold=85.0, keep_days=3, max_days=3):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(es.handler), base_url="http://es") as client:
            return await guard_mod.guard(client, threshold, keep_days, max_days=max_days, now=NOW)
    return _LOOP.run_until_complete(go())


def test_below_threshold_touches_nothing():
    es = FakeES(days=5)  # 80%
    result = run(es)
    assert result["status"] == "ok" and result["days_deleted"] == 0
    assert not any("delete_by_query" in c for c in es.calls)


def test_deletes_oldest_days_until_below_threshold():
    es = FakeES(days=10)  # 90%: two days must go to reach 86, three for 84
    result = run(es)
    assert result["status"] == "freed" and result["days_deleted"] == 3
    assert result["percent_before"] == 90 and result["percent_after"] == 84
    assert result["documents_deleted"] == 3000
    oldest_left = min(es.live)
    assert oldest_left == (NOW - timedelta(days=6)).date()  # the three oldest days are gone
    assert es.calls.count("POST /logs/_forcemerge") == 3  # disk is freed after each day


def test_the_newest_days_are_never_deleted():
    es = FakeES(days=5, base=80)  # 90% with 5 days of logs; the newest 3 days are protected
    result = run(es, keep_days=3)
    # the 4-day-old day goes; the 3-day-old day reaches into the protected window and stays
    assert result["status"] == "blocked" and result["days_deleted"] == 1
    assert len(es.live) == 4
    assert min(es.live) == (NOW - timedelta(days=3)).date()


def test_a_disk_filled_by_something_else_is_reported_not_emptied():
    es = FakeES(days=0, other=20)  # 90% and no logs at all
    result = run(es)
    assert result["status"] == "blocked" and result["days_deleted"] == 0


def test_one_run_deletes_at_most_max_days():
    es = FakeES(days=20, base=60)  # 100%
    result = run(es, max_days=2)
    assert result["status"] == "still_full" and result["days_deleted"] == 2
    assert len(es.live) == 18


def test_a_failed_task_raises():
    class Failing(FakeES):
        def handler(self, request):
            if request.url.path.startswith("/_tasks/"):
                return httpx.Response(200, json={"completed": True, "error": {"type": "search_phase_execution"}})
            return super().handler(request)
    with pytest.raises(RuntimeError, match="failed"):
        run(Failing(days=10))


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.mark.parametrize("event,title,level", [
    ("es_disk_pressure", "Elasticsearch Disk Full - Old Logs Deleted Early", "medium"),
    ("es_disk_full", "Elasticsearch Disk Full - Ingest At Risk", "critical"),
])
def test_health_events_raise_alerts(event, title, level):
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    line = health_line(event, status="freed", threshold=85.0, percent_before=90.0, percent_after=84.0,
                       days_deleted=3, deleted_before="2026-11-09T00:00:00+00:00")
    fields, _ = dec.decode_named("siem_agent", line)
    view = dict(fields, raw_message=line, log_type="siem_agent", hostname="elasticsearch")
    got = {m["title"]: m["level"] for m in _LOOP.run_until_complete(sig.evaluate(view))}
    assert got.get(title) == level
