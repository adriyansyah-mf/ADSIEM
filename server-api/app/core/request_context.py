"""Who is calling: client address, user agent and request line, kept for the
length of one HTTP request so the audit log (services/audit.py) records them
without every route passing them along.

The address is X-Real-IP, which nginx sets from $remote_addr on every proxied
location and so overwrites whatever a client sends (see core/limiter.py for
why X-Forwarded-For is not used). Without nginx it is the socket's peer."""
from __future__ import annotations

from contextvars import ContextVar

_current: ContextVar[dict | None] = ContextVar("request_context", default=None)


def current() -> dict:
    return _current.get() or {}


def _headers(scope) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        out[key.decode("latin-1").lower()] = value.decode("latin-1", errors="replace")
    return out


class RequestContextMiddleware:
    """Plain ASGI middleware, so background tasks that run after the response
    (most audit writes) still see the request's context."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = _headers(scope)
        client = scope.get("client")
        ip = headers.get("x-real-ip", "").strip() or (client[0] if client else "")
        token = _current.set({
            "ip": ip[:64] or None,
            "user_agent": headers.get("user-agent", "")[:512] or None,
            "request": f"{scope.get('method', '')} {scope.get('path', '')}"[:300],
        })
        try:
            await self.app(scope, receive, send)
        finally:
            _current.reset(token)
