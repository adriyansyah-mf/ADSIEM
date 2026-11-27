"""Search page histogram + field facets (app/services/telemetry_facets.py)."""
from datetime import datetime, timedelta, timezone

import pytest

from app.services import telemetry_facets as tf


def test_time_filter_bounds():
    assert tf.time_filter(None, None) is None
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f = tf.time_filter(since, None)
    assert f == {"range": {"created_at": {"gte": since.isoformat()}}}


def test_interval_targets_about_48_bars():
    end = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert tf._interval(end - timedelta(hours=4), end) == "5m"
    assert tf._interval(end - timedelta(hours=24), end) == "30m"
    assert tf._interval(end - timedelta(days=7), end) == "6h"
    assert tf._interval(end - timedelta(days=60), end) == "1d"


@pytest.mark.asyncio
async def test_facets_shapes_aggregation(monkeypatch):
    seen = {}

    async def fake_aggregate(query, aggs, size=0):
        seen["query"], seen["aggs"] = query, aggs
        return {"total": 7, "aggregations": {
            "histogram": {"buckets": [{"key": 1, "key_as_string": "2026-01-01T00:00:00Z", "doc_count": 7}]},
            "top:log_type": {"buckets": [{"key": "sysmon", "doc_count": 5}, {"key": "auth", "doc_count": 2}]},
        }}

    monkeypatch.setattr(tf, "aggregate", fake_aggregate)
    since = datetime.now(timezone.utc) - timedelta(hours=4)
    out = await tf.facets([{"term": {"group_id": "g1"}}], ["log_type", "agent_id"], since, None)

    assert out["total"] == 7
    assert out["histogram"] == [{"t": "2026-01-01T00:00:00Z", "count": 7}]
    assert out["facets"][0] == {"field": "log_type", "values": [{"value": "sysmon", "count": 5}, {"value": "auth", "count": 2}]}
    assert out["facets"][1] == {"field": "agent_id", "values": []}
    # group scope kept, and a window is added when the caller gave none
    filters = seen["query"]["bool"]["filter"]
    assert {"term": {"group_id": "g1"}} in filters
    assert any("range" in f for f in filters)
    assert seen["aggs"]["histogram"]["date_histogram"]["fixed_interval"] == "5m"
