from __future__ import annotations
import ipaddress
from typing import Any
from urllib.parse import quote
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider


class OTXProvider(ThreatIntelProvider):
    name = "otx"

    def __init__(self, cfg: TIConfig) -> None:
        self._key = cfg.otx_api_key or ""
        self._tls = cfg.http_verify_tls

    def _h(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": self._key}

    async def _get(self, url: str) -> dict[str, Any]:
        if not self._key:
            return {"skipped": True, "reason": "no API key"}
        async with httpx.AsyncClient(timeout=40.0, verify=self._tls) as c:
            r = await c.get(url, headers=self._h())
            if r.status_code == 404:
                return {"not_found": True}
            if r.status_code == 400:
                return {"skipped": True, "reason": "bad_request"}
            r.raise_for_status()
            return r.json()

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        try:
            parsed = ipaddress.ip_address(ip.strip())
        except ValueError:
            return {"skipped": True, "reason": "invalid ip"}
        family = "IPv4" if parsed.version == 4 else "IPv6"
        return await self._get(f"https://otx.alienvault.com/api/v1/indicators/{family}/{quote(str(parsed), safe=':')}/general")

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general")

    async def lookup_url(self, url: str) -> dict[str, Any]:
        seg = quote(url.strip(), safe="")
        if not seg:
            return {"skipped": True, "reason": "empty_url"}
        return await self._get(f"https://otx.alienvault.com/api/v1/indicators/url/{seg}/general")

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return await self._get(f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general")
