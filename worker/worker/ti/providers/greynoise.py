from __future__ import annotations
import ipaddress
from typing import Any
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider


class GreyNoiseProvider(ThreatIntelProvider):
    name = "greynoise"

    def __init__(self, cfg: TIConfig) -> None:
        self._key = cfg.greynoise_api_key or ""
        self._enabled = cfg.greynoise_enrich_ips
        self._timeout = cfg.greynoise_timeout_seconds
        self._tls = cfg.http_verify_tls

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        if not self._enabled:
            return {"skipped": True, "reason": "disabled"}
        try:
            parsed = ipaddress.ip_address(ip.strip())
        except ValueError:
            return {"skipped": True, "reason": "invalid ip"}
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
            return {"skipped": True, "reason": "non_public_ip"}
        target = parsed.compressed
        headers: dict[str, str] = {}
        if self._key:
            headers["key"] = self._key
            url = f"https://api.greynoise.io/v2/noise/context/{target}"
        else:
            url = f"https://api.greynoise.io/v3/community/{target}"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(min(self._timeout, 60.0)), verify=self._tls) as c:
                r = await c.get(url, headers=headers or None)
                if r.status_code == 404:
                    return {"not_found": True}
                if r.status_code == 429:
                    return {"skipped": True, "reason": "rate_limited"}
                if r.status_code in (401, 403) and self._key:
                    return {"skipped": True, "reason": "unauthorized"}
                if r.status_code >= 400:
                    return {"skipped": True, "reason": "http_error", "status": r.status_code}
                return r.json()
        except httpx.TimeoutException:
            return {"skipped": True, "reason": "timeout"}
        except httpx.HTTPError as e:
            return {"skipped": True, "reason": "http_error_exc", "detail": repr(e)}

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return {"skipped": True, "reason": "ip-only"}

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return {"skipped": True}

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return {"skipped": True}
