from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from worker.sla_escalation import (
    DEFAULT_BREACH_MINUTES,
    DEFAULT_WARN_MINUTES,
    MAX_ESCALATIONS_PER_CYCLE,
    _check_sla_escalations,
    due_thresholds,
)


# ── pure logic: due_thresholds ────────────────────────────────────


def test_no_threshold_due_when_alert_is_young() -> None:
    assert due_thresholds(alert_age_minutes=5, warn_minutes=45, breach_minutes=60, already_notified=set()) == []


def test_warn_due_once_age_crosses_warn_minutes() -> None:
    assert due_thresholds(50, warn_minutes=45, breach_minutes=60, already_notified=set()) == ["warn"]


def test_both_due_when_age_crosses_breach_directly() -> None:
    assert due_thresholds(90, warn_minutes=45, breach_minutes=60, already_notified=set()) == ["warn", "breach"]


def test_already_notified_thresholds_are_not_repeated() -> None:
    assert due_thresholds(90, warn_minutes=45, breach_minutes=60, already_notified={"warn"}) == ["breach"]
    assert due_thresholds(90, warn_minutes=45, breach_minutes=60, already_notified={"warn", "breach"}) == []


def test_default_thresholds_are_ordered_warn_before_breach_per_severity() -> None:
    for severity in DEFAULT_WARN_MINUTES:
        assert DEFAULT_WARN_MINUTES[severity] < DEFAULT_BREACH_MINUTES[severity]


# ── _check_sla_escalations: dedup and tenant-override wiring ──────


class _FakeAlert:
    def __init__(self, id_, group_id, severity, status, created_at, title="t", source_ip=None, hostname=None):
        self.id = id_
        self.group_id = group_id
        self.severity = severity
        self.status = status
        self.created_at = created_at
        self.title = title
        self.source_ip = source_ip
        self.hostname = hostname


class _FakeScalars:
    def __init__(self, values):
        self._values = values

    def all(self):
        return self._values


class _FakeResult:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return _FakeScalars(self._values)


class _FakeSession:
    def __init__(self, results_by_call: list):
        self._results = list(results_by_call)
        self.added: list = []
        self.commits = 0

    async def execute(self, *_a, **_kw):
        if self._results:
            return self._results.pop(0)
        return _FakeResult([])  # e.g. extra per-threshold webhook-config lookups

    def add(self, instance) -> None:
        self.added.append(instance)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        pass


@pytest.mark.asyncio
async def test_check_sla_escalations_emits_for_breached_alert_with_no_policy_override() -> None:
    alert_id = uuid.uuid4()
    old_alert = _FakeAlert(
        alert_id, "blue", "critical", "new",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=20),  # past default critical breach (15m)
    )
    session = _FakeSession([
        _FakeResult([old_alert]),   # open alerts
        _FakeResult([]),            # sla_policies (no overrides)
        _FakeResult([]),            # sla_notifications (none yet)
        _FakeResult([]),            # webhook_configs (none configured)
    ])

    with (
        patch("worker.sla_escalation.AsyncSessionLocal") as session_factory,
        patch("worker.sla_escalation.send_alert_email", new=AsyncMock()) as email_mock,
    ):
        session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        await _check_sla_escalations()

    # Both warn and breach are due at once (20m > breach=15m > warn=10m for critical)
    notifications = [obj for obj in session.added if type(obj).__name__ == "SlaNotification"]
    assert {n.threshold for n in notifications} == {"warn", "breach"}
    assert email_mock.await_count == 2  # one email per threshold emitted


@pytest.mark.asyncio
async def test_check_sla_escalations_skips_already_notified_threshold() -> None:
    alert_id = uuid.uuid4()
    old_alert = _FakeAlert(
        alert_id, "blue", "critical", "new",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    existing_notification = type("N", (), {"alert_id": alert_id, "threshold": "warn"})()
    session = _FakeSession([
        _FakeResult([old_alert]),
        _FakeResult([]),
        _FakeResult([existing_notification]),
        _FakeResult([]),
    ])

    with (
        patch("worker.sla_escalation.AsyncSessionLocal") as session_factory,
        patch("worker.sla_escalation.send_alert_email", new=AsyncMock()) as email_mock,
    ):
        session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        await _check_sla_escalations()

    notifications = [obj for obj in session.added if type(obj).__name__ == "SlaNotification"]
    assert {n.threshold for n in notifications} == {"breach"}  # warn already sent, only breach is new
    assert email_mock.await_count == 1


@pytest.mark.asyncio
async def test_check_sla_escalations_respects_tenant_policy_override() -> None:
    alert_id = uuid.uuid4()
    # Only 3 minutes old -- would NOT breach under the default critical policy (15m),
    # but this tenant's override sets breach_minutes=2.
    young_alert = _FakeAlert(
        alert_id, "blue", "critical", "new",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=3),
    )
    override = type("P", (), {"group_id": "blue", "severity": "critical", "warn_minutes": 1, "breach_minutes": 2})()
    session = _FakeSession([
        _FakeResult([young_alert]),
        _FakeResult([override]),
        _FakeResult([]),
        _FakeResult([]),
    ])

    with (
        patch("worker.sla_escalation.AsyncSessionLocal") as session_factory,
        patch("worker.sla_escalation.send_alert_email", new=AsyncMock()),
    ):
        session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        await _check_sla_escalations()

    notifications = [obj for obj in session.added if type(obj).__name__ == "SlaNotification"]
    assert {n.threshold for n in notifications} == {"warn", "breach"}


@pytest.mark.asyncio
async def test_large_backlog_of_overdue_alerts_is_capped_per_cycle() -> None:
    """A first-deploy scenario: many pre-existing open alerts are already
    long overdue. Without a cap, all of them fire in the same cycle -- this
    is exactly the flood discovered during live verification, reproduced
    here to prove it can't regress."""
    old_alerts = [
        _FakeAlert(
            uuid.uuid4(), "blue", "critical", "new",
            created_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        for _ in range(MAX_ESCALATIONS_PER_CYCLE + 20)
    ]
    session = _FakeSession([
        _FakeResult(old_alerts),
        _FakeResult([]),  # no policy overrides
        _FakeResult([]),  # no prior notifications
        _FakeResult([]),  # webhook configs (repeated for every emitted escalation)
    ])

    with (
        patch("worker.sla_escalation.AsyncSessionLocal") as session_factory,
        patch("worker.sla_escalation.send_alert_email", new=AsyncMock()) as email_mock,
    ):
        session_factory.return_value.__aenter__ = AsyncMock(return_value=session)
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        await _check_sla_escalations()

    notifications = [obj for obj in session.added if type(obj).__name__ == "SlaNotification"]
    # Each alert is due for BOTH warn and breach, but the cycle stops at
    # exactly MAX_ESCALATIONS_PER_CYCLE (alert, threshold) pairs -- not per alert.
    assert len(notifications) == MAX_ESCALATIONS_PER_CYCLE
    assert email_mock.await_count == MAX_ESCALATIONS_PER_CYCLE
