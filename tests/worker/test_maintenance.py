from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from worker.maintenance import (
    _all_tenants,
    _enforce_tenant_quota,
    _purge_tenant_alerts,
    _purge_tenant_logs,
    effective_policy,
)


def _policy(**kwargs):
    defaults = dict(group_id="blue", log_retention_days=None, alert_retention_days=None, storage_quota_docs=None)
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# -- effective_policy (pure) --

def test_no_policy_uses_global_defaults():
    log_days, alert_days, quota = effective_policy(None, global_log_days=30, global_alert_days=180)
    assert (log_days, alert_days, quota) == (30, 180, None)


def test_policy_overrides_only_log_days_inherits_rest():
    policy = _policy(log_retention_days=7)
    log_days, alert_days, quota = effective_policy(policy, global_log_days=30, global_alert_days=180)
    assert log_days == 7
    assert alert_days == 180
    assert quota is None


def test_policy_can_override_all_three():
    policy = _policy(log_retention_days=7, alert_retention_days=14, storage_quota_docs=1000)
    log_days, alert_days, quota = effective_policy(policy, global_log_days=30, global_alert_days=180)
    assert (log_days, alert_days, quota) == (7, 14, 1000)


def test_policy_can_explicitly_disable_retention_with_zero():
    policy = _policy(log_retention_days=0)
    log_days, _, _ = effective_policy(policy, global_log_days=30, global_alert_days=180)
    assert log_days == 0  # 0 is a real override, not "use default"


# -- _purge_tenant_logs / _purge_tenant_alerts --

@pytest.mark.asyncio
async def test_purge_tenant_logs_skips_when_days_is_zero():
    with patch("worker.maintenance.es_delete_by_query", new=AsyncMock()) as mock_delete:
        deleted = await _purge_tenant_logs("blue", 0)
    assert deleted == 0
    mock_delete.assert_not_called()


@pytest.mark.asyncio
async def test_purge_tenant_logs_scopes_query_to_tenant():
    with patch("worker.maintenance.es_delete_by_query", new=AsyncMock(return_value=42)) as mock_delete:
        deleted = await _purge_tenant_logs("blue", 30)
    assert deleted == 42
    query = mock_delete.call_args.args[0]
    assert {"term": {"group_id": "blue"}} in query["bool"]["filter"]


class _FakeExecuteResult:
    def __init__(self, rowcount=0, scalars_values=None):
        self.rowcount = rowcount
        self._scalars_values = scalars_values or []

    def scalars(self):
        return self

    def all(self):
        return self._scalars_values


class _FakeDb:
    def __init__(self, results: list | None = None):
        self._results = list(results or [])

    async def execute(self, *_a, **_kw):
        return self._results.pop(0)


@pytest.mark.asyncio
async def test_purge_tenant_alerts_skips_when_days_is_zero():
    db = _FakeDb()
    deleted = await _purge_tenant_alerts(db, "blue", 0)
    assert deleted == 0


@pytest.mark.asyncio
async def test_purge_tenant_alerts_returns_rowcount():
    db = _FakeDb([_FakeExecuteResult(rowcount=5)])
    deleted = await _purge_tenant_alerts(db, "blue", 180)
    assert deleted == 5


# -- _enforce_tenant_quota --

@pytest.mark.asyncio
async def test_enforce_quota_noop_when_no_quota_set():
    with patch("worker.maintenance.find_quota_cutoff", new=AsyncMock()) as mock_cutoff:
        deleted = await _enforce_tenant_quota("blue", None)
    assert deleted == 0
    mock_cutoff.assert_not_called()


@pytest.mark.asyncio
async def test_enforce_quota_noop_when_under_quota():
    with patch("worker.maintenance.find_quota_cutoff", new=AsyncMock(return_value=None)):
        deleted = await _enforce_tenant_quota("blue", 1000)
    assert deleted == 0


@pytest.mark.asyncio
async def test_enforce_quota_deletes_excess_docs_up_to_cutoff():
    with patch("worker.maintenance.find_quota_cutoff", new=AsyncMock(return_value="2026-01-01T00:00:00Z")), \
         patch("worker.maintenance.es_delete_by_query", new=AsyncMock(return_value=250)) as mock_delete:
        deleted = await _enforce_tenant_quota("blue", 1000)
    assert deleted == 250
    query = mock_delete.call_args.args[0]
    assert {"term": {"group_id": "blue"}} in query["bool"]["filter"]
    assert {"range": {"created_at": {"lte": "2026-01-01T00:00:00Z"}}} in query["bool"]["filter"]


# -- _all_tenants --

@pytest.mark.asyncio
async def test_all_tenants_unions_logs_alerts_and_policies():
    db = _FakeDb([
        _FakeExecuteResult(scalars_values=["blue", "red"]),   # distinct alert group_ids
        _FakeExecuteResult(scalars_values=["green"]),          # policy group_ids
    ])
    with patch("worker.maintenance.distinct_group_ids", new=AsyncMock(return_value=["blue", "yellow"])):
        tenants = await _all_tenants(db)
    assert tenants == {"blue", "red", "green", "yellow"}
