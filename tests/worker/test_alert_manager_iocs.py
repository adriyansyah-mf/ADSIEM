# tests/worker/test_alert_manager_iocs.py
"""create_alert indexes the alert's indicators after commit, and never fails because of it."""
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from worker import alert_iocs, alert_manager, settings_cache


class _Result:
    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return SimpleNamespace(all=lambda: [])


class _Session:
    """Dedup select -> None, webhook select -> no rows; flush assigns id and created_at."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, _query):
        return _Result()

    def add(self, obj):
        self.alert = obj

    async def flush(self):
        self.alert.id = uuid.uuid4()
        self.alert.created_at = datetime(2026, 11, 7, tzinfo=timezone.utc)

    async def commit(self):
        pass


@pytest.fixture
def faked(monkeypatch):
    async def false(*a, **k):
        return False

    async def zero(*a, **k):
        return 0.0

    async def noop(*a, **k):
        return None

    async def no_exclusions(key, default=""):
        return default

    redis = SimpleNamespace(publish=noop, rpush=noop)

    async def get_redis():
        return redis

    monkeypatch.setattr(alert_manager, "_is_suppressed", false)
    monkeypatch.setattr(alert_manager, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(alert_manager, "get_redis", get_redis)
    monkeypatch.setattr(alert_manager, "_should_ai_investigate", false)
    monkeypatch.setattr(alert_manager, "_get_entity_risk_max", zero)
    monkeypatch.setattr(alert_manager, "run_soar_playbooks", noop)
    monkeypatch.setattr(alert_manager, "send_alert_email", noop)
    monkeypatch.setattr(settings_cache, "get_setting", no_exclusions)


MATCH = {"title": "Beacon", "level": "high", "matched_fields": {}}


async def test_create_alert_indexes_source_ip(faked, monkeypatch):
    got = []

    async def index_docs(docs):
        got.extend(docs)
        return 0

    monkeypatch.setattr(alert_iocs, "index_docs", index_docs)
    agent = uuid.uuid4()
    alert_id = await alert_manager.create_alert(MATCH, None, agent, "blue", "45.33.32.156", "h1")
    assert len(got) == 1
    doc = got[0][1]
    assert (doc["type"], doc["value"]) == ("ip", "45.33.32.156")
    assert doc["alert_id"] == str(alert_id)
    assert (doc["group_id"], doc["severity"], doc["rule_title"], doc["agent_id"]) == (
        "blue", "high", "Beacon", str(agent))


async def test_create_alert_survives_indexing_failure(faked, monkeypatch):
    async def boom(docs):
        raise RuntimeError("es down")

    monkeypatch.setattr(alert_iocs, "index_docs", boom)
    assert await alert_manager.create_alert(MATCH, None, None, "blue", "45.33.32.156", "h1") is not None
