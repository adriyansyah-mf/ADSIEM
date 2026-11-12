# tests/worker/test_alert_below_threshold.py
"""Alerts under ai_min_severity are created as below_threshold, not new: the
AI (and its hourly backfill) leaves them alone, so only what reaches the
threshold gets acknowledged/escalated by the AI."""
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from worker import alert_iocs, alert_manager, settings_cache

CREATED = []


class _Result:
    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return SimpleNamespace(all=lambda: [])


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, _query):
        return _Result()

    def add(self, obj):
        self.alert = obj
        CREATED.append(obj)

    async def flush(self):
        self.alert.id = uuid.uuid4()
        self.alert.created_at = datetime(2026, 11, 13, tzinfo=timezone.utc)

    async def commit(self):
        pass


@pytest.fixture
def harness(monkeypatch):
    CREATED.clear()
    queued = []
    setting = {"ai_min_severity": "high"}

    async def false(*a, **k):
        return False

    async def zero(*a, **k):
        return 0.0

    async def noop(*a, **k):
        return None

    async def rpush(key, value):
        queued.append(value)

    async def get_setting(key, default=""):
        return setting.get(key, default)

    redis = SimpleNamespace(publish=noop, rpush=rpush, sadd=noop, expire=noop)

    async def get_redis():
        return redis

    monkeypatch.setattr(alert_manager, "_is_suppressed", false)
    monkeypatch.setattr(alert_manager, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(alert_manager, "get_redis", get_redis)
    monkeypatch.setattr(alert_manager, "get_setting", get_setting)
    monkeypatch.setattr(alert_manager, "_get_entity_risk_max", zero)
    monkeypatch.setattr(alert_manager, "run_soar_playbooks", noop)
    monkeypatch.setattr(alert_manager, "send_alert_email", noop)
    monkeypatch.setattr(settings_cache, "get_setting", get_setting)

    async def index_docs(docs):
        return 0
    monkeypatch.setattr(alert_iocs, "index_docs", index_docs)
    return SimpleNamespace(queued=queued, setting=setting)


@pytest.mark.parametrize("level,status,to_ai", [
    ("critical", "new", True),
    ("high", "new", True),
    ("medium", "below_threshold", False),
    ("low", "below_threshold", False),
])
async def test_status_follows_the_ai_threshold(harness, level, status, to_ai):
    await alert_manager.create_alert({"title": "t", "level": level, "matched_fields": {}},
                                     None, None, "blue", "203.0.113.9", "h1")
    assert CREATED[-1].status == status
    assert bool(harness.queued) == to_ai


async def test_threshold_is_a_setting(harness):
    harness.setting["ai_min_severity"] = "medium"
    await alert_manager.create_alert({"title": "t", "level": "medium", "matched_fields": {}},
                                     None, None, "blue", "203.0.113.9", "h1")
    assert CREATED[-1].status == "new" and harness.queued


async def test_a_bad_setting_falls_back_to_high(harness):
    harness.setting["ai_min_severity"] = "hgih"  # must not turn every alert below_threshold
    assert await alert_manager._should_ai_investigate("critical")
    assert not await alert_manager._should_ai_investigate("medium")
    harness.setting["ai_min_severity"] = " Medium "
    assert await alert_manager._should_ai_investigate("medium")


def test_below_threshold_alerts_still_deduplicate():
    assert "below_threshold" in alert_manager.OPEN_STATUSES


def test_soar_can_set_it():
    from worker.soar.graph import ALERT_STATUSES
    assert "below_threshold" in ALERT_STATUSES
