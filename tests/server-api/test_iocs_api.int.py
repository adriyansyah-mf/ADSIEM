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
    "types": {"buckets": [
        {"key": "url", "doc_count": 3, "distinct": {"value": 1}},
        {"key": "ip", "doc_count": 5, "distinct": {"value": 2}},
    ]},
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
    assert body["aggs"]["types"]["aggs"]["distinct"] == {"cardinality": {"field": "ioc_key"}}
    assert r.json() == {"total": 1, "type_counts": {"url": 1, "ip": 2}, "items": [{
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


async def test_domain_rows_report_whether_the_group_blocks_them(iocs_api):
    from app.models.models import WebBlockEntry, WebBlockPolicy
    async with iocs_api.sessions() as db:
        db.add(WebBlockPolicy(group_id="blue", enabled=True))
        db.add(WebBlockEntry(domain="evil.example", group_id="blue", source="manual"))
        await db.commit()
    iocs_api.reply["value"] = {"aggregations": {"types": {"buckets": []}, "matched": {"count": {"value": 3}, "iocs": {"buckets": [
        {"key": k, "alerts": {"value": 1}, "hosts": {"value": 1}, "first_seen": {}, "last_seen": {}, "max_severity": {}}
        for k in ("domain:evil.example", "url:http://evil.example/a", "ip:45.33.32.156")]}}}}
    items = (await iocs_api.api.get("/api/iocs")).json()["items"]
    assert [i["blocked"] for i in items] == [True, True, None]
