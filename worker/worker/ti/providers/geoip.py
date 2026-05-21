from __future__ import annotations
from typing import Any
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider


class GeoIPProvider(ThreatIntelProvider):
    name = "geoip_ipapi"

    def __init__(self, cfg: TIConfig) -> None:
        self._tls = cfg.http_verify_tls

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=self._tls) as c:
            r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp")
            r.raise_for_status()
            return r.json()

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return {"skipped": True}

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return {"skipped": True}

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return {"skipped": True}
