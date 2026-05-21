# tests/server-api/test_rbac.py
import pytest
from unittest.mock import MagicMock
from app.core.deps import require_permission

def make_user(role_name: str, perms: list[str]):
    user = MagicMock()
    user.role.name = role_name
    perms_list = []
    for p in perms:
        perm = MagicMock()
        perm.name = p
        perms_list.append(perm)
    user.role.permissions = perms_list
    return user

@pytest.mark.asyncio
async def test_superadmin_bypasses_all_permissions():
    user = make_user("superadmin", [])
    checker = require_permission("users:manage")
    result = await checker(user)
    assert result is user

@pytest.mark.asyncio
async def test_viewer_denied_manage_permission():
    from fastapi import HTTPException
    user = make_user("viewer", ["logs:read", "alerts:read"])
    checker = require_permission("users:manage")
    with pytest.raises(HTTPException) as exc_info:
        await checker(user)
    assert exc_info.value.status_code == 403

@pytest.mark.asyncio
async def test_analyst_allowed_alerts_update():
    user = make_user("analyst", ["logs:read", "alerts:read", "alerts:update"])
    checker = require_permission("alerts:update")
    result = await checker(user)
    assert result is user
