from __future__ import annotations
import base64
from typing import Any
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    def __init__(self, cfg: TIConfig) -> None:
        self._key = cfg.virustotal_api_key or ""
        self._tls = cfg.http_verify_tls

    def _h(self) -> dict[str, str]:
        return {"x-apikey": self._key}

    async def _get(self, url: str) -> dict[str, Any]:
        if not self._key:
            return {"skipped": True, "reason": "no API key"}
        async with httpx.AsyncClient(timeout=40.0, verify=self._tls) as c:
            r = await c.get(url, headers=self._h())
            if r.status_code == 404:
                return {"not_found": True}
            if r.status_code == 429:
                return {"skipped": True, "reason": "rate_limited"}
            if r.status_code in (400, 401, 403):
                return {"skipped": True, "reason": "client_error", "status": r.status_code}
            r.raise_for_status()
            return r.json()

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        return await self._get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}")

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"https://www.virustotal.com/api/v3/domains/{domain}")

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return await self._get(f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}")

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return await self._get(f"https://www.virustotal.com/api/v3/files/{h}")
