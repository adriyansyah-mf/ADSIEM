from __future__ import annotations
from typing import Any
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider

_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(ThreatIntelProvider):
    name = "urlhaus"

    def __init__(self, cfg: TIConfig) -> None:
        self._tls = cfg.http_verify_tls

    async def _post(self, url: str, data: dict) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0, verify=self._tls) as c:
            r = await c.post(url, data=data)
            if r.status_code in (401, 403):
                return {"skipped": True, "reason": "unauthorized"}
            if r.status_code == 429:
                return {"skipped": True, "reason": "rate_limited"}
            r.raise_for_status()
            return r.json()

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        return await self._post(f"{_BASE}/host/", {"host": ip})

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return await self._post(f"{_BASE}/host/", {"host": domain})

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return await self._post(f"{_BASE}/url/", {"url": url})

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        hx = (h or "").strip().lower()
        if len(hx) not in (32, 40, 64):
            return {"skipped": True, "reason": "invalid_hash"}
        return await self._post(f"{_BASE}/payload/", {"file_hash": hx})
