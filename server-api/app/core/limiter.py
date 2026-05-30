from slowapi import Limiter
from starlette.requests import Request


def _real_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host or "127.0.0.1"


limiter = Limiter(key_func=_real_ip)
