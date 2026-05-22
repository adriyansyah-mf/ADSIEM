from __future__ import annotations
import ipaddress
from typing import Any
import httpx
from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider


def _ripe_summary(data: dict[str, Any]) -> str | None:
    recs = data.get("records")
    if not isinstance(recs, list):
        return None
    bits: list[str] = []
    for block in recs[:4]:
        if not isinstance(block, list):
            continue
        for row in block:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key", "")).strip().lower()
            if key in ("netname", "origin", "descr", "org-name", "org", "country"):
                val = row.get("value")
                if val and str(val).strip():
                    bits.append(f"{key}={str(val).strip()[:120]}")
            if len(bits) >= 5:
                break
        if len(bits) >= 5:
            break
    return "; ".join(bits) if bits else None


class WhoisLookupProvider(ThreatIntelProvider):
    name = "whois_rdap"

    def __init__(self, cfg: TIConfig) -> None:
        self._timeout = cfg.whois_rdap_timeout_seconds
        self._tls = cfg.http_verify_tls

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        try:
            parsed = ipaddress.ip_address(ip.strip())
        except ValueError:
            return {"skipped": True, "reason": "invalid ip"}
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
            return {"skipped": True, "reason": "non_public_ip"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._tls) as c:
                r = await c.get(f"https://stat.ripe.net/data/whois/data.json?resource={parsed.compressed}")
                if r.status_code != 200:
                    return {"skipped": True, "reason": "ripe_http", "status": r.status_code}
                j = r.json()
        except (httpx.TimeoutException, httpx.HTTPError):
            return {"skipped": True, "reason": "timeout_or_error"}
        if not isinstance(j, dict) or j.get("status") != "ok":
            return {"skipped": True, "reason": "ripe_status"}
        inner = j.get("data")
        if not isinstance(inner, dict):
            return {"skipped": True, "reason": "ripe_shape"}
        summary = _ripe_summary(inner)
        return {"ripe_whois": True, "summary": summary}

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._tls) as c:
                r = await c.get(f"https://rdap.verisign.com/com/v1/domain/{domain}")
                if r.status_code == 404:
                    return {"not_found": True}
                if r.status_code >= 400:
                    return {"skipped": True, "reason": "http_error", "status": r.status_code}
                return {"rdap": True, "bytes": len(r.text)}
        except (httpx.TimeoutException, httpx.HTTPError):
            return {"skipped": True, "reason": "timeout_or_error"}

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return {"skipped": True}

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return {"skipped": True}
