"""The investigation review panel's size and rounds are whole numbers in
range: a typo is refused rather than silently clamped by the investigator."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.api.routes.settings import update_setting
from app.schemas.schemas import SettingUpdate


class _DB:
    def __init__(self, setting):
        self.setting = setting

    async def execute(self, _q):
        return SimpleNamespace(scalar_one_or_none=lambda: self.setting)

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


def _row(key, value):
    return SimpleNamespace(key=key, value=value, is_secret=False, description="", updated_by=None,
                           updated_at=datetime(2026, 11, 14, tzinfo=timezone.utc))


@pytest.mark.parametrize("key,value,stored", [
    ("investigation_debate_agents", " 0 ", "0"), ("investigation_debate_agents", "6", "6"),
    ("investigation_debate_rounds", "1", "1"), ("investigation_debate_rounds", "3", "3"),
])
async def test_in_range_is_saved(key, value, stored):
    row = _row(key, "2")
    await update_setting(key, SettingUpdate(value=value), BackgroundTasks(), _DB(row), SimpleNamespace(id=None))
    assert row.value == stored


@pytest.mark.parametrize("key,value", [
    ("investigation_debate_agents", "7"), ("investigation_debate_agents", "-1"),
    ("investigation_debate_agents", "three"), ("investigation_debate_rounds", "0"),
    ("investigation_debate_rounds", "4"), ("investigation_debate_rounds", ""),
])
async def test_out_of_range_is_refused(key, value):
    row = _row(key, "2")
    with pytest.raises(HTTPException) as exc:
        await update_setting(key, SettingUpdate(value=value), BackgroundTasks(), _DB(row), SimpleNamespace(id=None))
    assert exc.value.status_code == 422 and row.value == "2"
