from __future__ import annotations
from typing import Any
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"

    def __init__(self, cfg: TIConfig) -> None:
        self._key = cfg.abuseipdb_api_key or ""
        self._tls = cfg.http_verify_tls

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        if not self._key:
            return {"skipped": True, "reason": "no API key"}
        async with httpx.AsyncClient(timeout=30.0, verify=self._tls) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
            )
            r.raise_for_status()
            return r.json()

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return {"skipped": True, "reason": "ip-only"}

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return {"skipped": True, "reason": "ip-only"}

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return {"skipped": True, "reason": "ip-only"}
