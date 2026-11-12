from slowapi import Limiter
from starlette.requests import Request


def _real_ip(request: Request) -> str:
    """The client address to rate-limit on.

    X-Real-IP is set by nginx from $remote_addr on every proxied location
    (nginx/*.conf), replacing whatever the client sent. X-Forwarded-For is
    ignored: its first entry is whatever the client put there (prod nginx
    doesn't set it at all), so keying on it let a login brute force rotate a
    fake header past the limit. server-api isn't published outside siem-net,
    so the only way in is through nginx."""
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip:
        return real_ip
    return (request.client.host if request.client else None) or "127.0.0.1"


limiter = Limiter(key_func=_real_ip)
