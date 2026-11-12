"""The worker (re)creates the snapshot repository and SLM policy, and degrades
quietly when path.repo isn't configured."""
import json

import httpx

from worker import es_snapshots


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://es")


async def test_registers_repository_then_policy():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, json.loads(request.content or b"{}")))
        return httpx.Response(200, json={"acknowledged": True})

    async with _client(handler) as c:
        assert await es_snapshots.ensure(c)
    (m1, p1, repo), (m2, p2, policy) = calls
    assert (m1, p1) == ("PUT", f"/_snapshot/{es_snapshots.REPOSITORY}")
    assert repo == {"type": "fs", "settings": {"location": es_snapshots.REPOSITORY_PATH, "compress": True}}
    assert (m2, p2) == ("PUT", f"/_slm/policy/{es_snapshots.POLICY}")
    assert policy["repository"] == es_snapshots.REPOSITORY
    assert set(policy["config"]["indices"]) == {"logs", "alert_iocs"}
    assert policy["retention"]["expire_after"] == f"{es_snapshots.RETAIN_DAYS}d"
    assert policy["retention"]["min_count"] >= 1


async def test_missing_path_repo_is_reported_not_raised():
    def handler(request):
        return httpx.Response(500, json={"error": {"type": "repository_exception",
                                                    "reason": "location [...] doesn't match any of the locations "
                                                              "specified by path.repo"}})

    async with _client(handler) as c:
        assert await es_snapshots.ensure(c) is False


async def test_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("ES_SNAPSHOTS", "off")

    def handler(request):
        raise AssertionError("no request expected")

    async with _client(handler) as c:
        assert await es_snapshots.ensure(c) is False


async def test_last_status_reads_the_policy():
    def handler(request):
        return httpx.Response(200, json={es_snapshots.POLICY: {
            "last_success": {"snapshot_name": "adsiem-2026.11.12-a", "time_string": "2026-11-12T01:30:02.123Z"},
        }})

    async with _client(handler) as c:
        assert await es_snapshots.last_status(c) == {"last_success": "2026-11-12T01:30:02.123Z",
                                                      "last_failure": None}


async def test_last_status_converts_epoch_millis():
    # Elasticsearch 8.15 reports `time` only, as epoch milliseconds (seen live)
    def handler(request):
        return httpx.Response(200, json={es_snapshots.POLICY: {
            "last_success": {"snapshot_name": "s", "time": 1794468159083},
            "last_failure": {"snapshot_name": "f", "time": 1794381759083},
        }})

    async with _client(handler) as c:
        st = await es_snapshots.last_status(c)
    assert st["last_success"].startswith("2026-11-12T") and st["last_failure"].startswith("2026-11-11T")
