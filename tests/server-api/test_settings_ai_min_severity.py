# tests/server-api/test_settings_ai_min_severity.py
"""ai_min_severity decides which alerts are created as below_threshold, so
the settings API only takes a real severity (a typo would be worse than a
422)."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.api.routes.settings import update_setting
from app.schemas.schemas import SettingUpdate


class _Setting(SimpleNamespace):
    pass


class _DB:
    def __init__(self, setting):
        self.setting = setting

    async def execute(self, _q):
        return SimpleNamespace(scalar_one_or_none=lambda: self.setting)

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


def _row():
    return _Setting(key="ai_min_severity", value="high", is_secret=False, description="", updated_by=None,
                    updated_at=datetime(2026, 11, 13, tzinfo=timezone.utc))


@pytest.mark.parametrize("value,stored", [("medium", "medium"), (" Critical ", "critical")])
async def test_valid_severity_is_saved_normalised(value, stored):
    row = _row()
    await update_setting("ai_min_severity", SettingUpdate(value=value), BackgroundTasks(), _DB(row),
                         SimpleNamespace(id=None))
    assert row.value == stored


@pytest.mark.parametrize("value", ["hgih", "", "urgent"])
async def test_anything_else_is_refused(value):
    row = _row()
    with pytest.raises(HTTPException) as exc:
        await update_setting("ai_min_severity", SettingUpdate(value=value), BackgroundTasks(), _DB(row),
                             SimpleNamespace(id=None))
    assert exc.value.status_code == 422 and row.value == "high"
