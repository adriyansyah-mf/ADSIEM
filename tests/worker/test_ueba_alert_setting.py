# tests/worker/test_ueba_alert_setting.py
"""ueba_alerts_enabled (default false): a UEBA anomaly is recorded and raises
the entity's risk, but raises no alert, so no AI triage and no case."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import numpy as np  # noqa: E402
import pytest  # noqa: E402

from worker.ueba import scorer  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.kv = {}

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, ex=None):
        self.kv[key] = value

    async def setex(self, key, ttl, value):
        self.kv[key] = value

    async def exists(self, key):
        return key in self.kv


class FakeDB:
    def __init__(self):
        self.added = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, model, key):
        return None

    def add(self, row):
        self.added.append(row)

    async def execute(self, stmt):
        return None

    async def commit(self):
        return None


class Forest:
    def decision_function(self, vec):
        return np.array([-0.5])


class Bundle:
    model = Forest()
    feature_keys = ["login_failures"]
    baseline = {}


@pytest.fixture()
def harness(monkeypatch):
    db, raised, setting = FakeDB(), [], {}

    async def raise_alert(*args):
        raised.append(args)
        return "alert-1"

    async def get_setting(key, default=""):
        return setting.get(key, default)

    async def population(redis, entity_type, group_id, bundle):
        return {}, "all entities"

    reasons = [{"feature": "login_failures", "text": "500 failed logins", "security": True}]
    monkeypatch.setattr(scorer, "AsyncSessionLocal", lambda: db)
    monkeypatch.setattr(scorer, "_raise_alert", raise_alert)
    monkeypatch.setattr(scorer, "get_setting", get_setting)
    monkeypatch.setattr(scorer, "_population", population)
    monkeypatch.setattr(scorer, "explain", lambda *a: reasons)
    monkeypatch.setattr(scorer, "assess", lambda *a: 0.95)  # strong: past the cold-entity guard
    monkeypatch.setattr(scorer, "mitre_for", lambda *a: [])
    return db, raised, setting


def _score(redis=None):
    asyncio.run(scorer._handle_score(redis or FakeRedis(), "ip", "45.156.87.6", Bundle(),
                                     {"login_failures": 500}, "default", {}))


def test_anomaly_without_alert_by_default(harness):
    db, raised, _ = harness
    _score()
    anomalies = [r for r in db.added if isinstance(r, scorer.UebaAnomaly)]
    assert raised == []
    assert len(anomalies) == 1 and anomalies[0].alert_id is None and anomalies[0].risk_score > 0


@pytest.mark.parametrize("value,alerts", [("true", True), ("TRUE ", True), ("false", False), ("", False), ("yes", False)])
def test_setting_turns_alerts_on(harness, value, alerts):
    db, raised, setting = harness
    setting["ueba_alerts_enabled"] = value
    _score()
    anomaly = next(r for r in db.added if isinstance(r, scorer.UebaAnomaly))
    assert bool(raised) is alerts
    assert anomaly.alert_id == ("alert-1" if alerts else None)


def test_no_cooldown_is_spent_while_off(harness):
    """Turning alerts on later is not held back by a cooldown set while off."""
    _, raised, setting = harness
    r = FakeRedis()
    _score(r)
    assert not any(k.startswith("ueba:cd:") for k in r.kv)
    setting["ueba_alerts_enabled"] = "true"
    r.kv.pop("ueba:rec:ip:45.156.87.6")  # a new anomaly window
    _score(r)
    assert len(raised) == 1
