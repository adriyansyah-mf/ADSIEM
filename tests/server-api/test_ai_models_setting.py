# tests/server-api/test_ai_models_setting.py
"""The model picker lists what 9router offers (/v1/models)."""
import asyncio

import httpx
import pytest
from fastapi import HTTPException

from app.api.routes.settings import list_ai_models


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _DB:
    def __init__(self, key):
        self.key = key

    async def execute(self, _):
        return _Result(self.key)


def _fake_client(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


def test_lists_9router_models(monkeypatch):
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"object": "list", "data": [
            {"id": "cc/claude-opus-4"}, {"id": "combo"}, {"id": "gemini/gemini-2.5-pro"}, {"id": "combo"}]})
    _fake_client(monkeypatch, handler)
    out = asyncio.run(list_ai_models(_DB("k-123"), None))
    assert out == {"models": ["cc/claude-opus-4", "combo", "gemini/gemini-2.5-pro"]}
    assert seen == {"auth": "Bearer k-123", "path": "/v1/models"}


def test_needs_a_key_and_reports_9router_errors(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(list_ai_models(_DB(None), None))
    assert exc.value.status_code == 422
    _fake_client(monkeypatch, lambda request: httpx.Response(401, json={"error": "bad key"}))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(list_ai_models(_DB("k"), None))
    assert exc.value.status_code == 502 and "9router /models failed" in exc.value.detail
