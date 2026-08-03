from __future__ import annotations
import os
import threading
from typing import Any

import geoip2.database
import geoip2.errors

from worker.ti.config import TIConfig
from worker.ti.providers.base import ThreatIntelProvider

_GEOIP_DIR = os.environ.get("GEOIP_DIR", "/app/mmdb")

_lock = threading.Lock()
_city_reader: geoip2.database.Reader | None = None
_asn_reader: geoip2.database.Reader | None = None
_load_attempted = False


def _get_readers() -> tuple[geoip2.database.Reader | None, geoip2.database.Reader | None]:
    # Readers are opened once and reused — geoip2.database.Reader wraps a
    # memory-mapped file and is safe for concurrent reads across threads.
    global _city_reader, _asn_reader, _load_attempted
    with _lock:
        if _load_attempted:
            return _city_reader, _asn_reader
        _load_attempted = True
        city_path = os.path.join(_GEOIP_DIR, "GeoLite2-City.mmdb")
        asn_path = os.path.join(_GEOIP_DIR, "GeoLite2-ASN.mmdb")
        if os.path.exists(city_path):
            _city_reader = geoip2.database.Reader(city_path)
        if os.path.exists(asn_path):
            _asn_reader = geoip2.database.Reader(asn_path)
        return _city_reader, _asn_reader


class GeoIPProvider(ThreatIntelProvider):
    """Local MaxMind GeoLite2 (.mmdb) lookups — no external API call, no
    rate limit, and the investigated IP never leaves this host. Falls back
    to a status="fail" result (same shape the ip-api.com version used to
    return) if the .mmdb files aren't mounted or the IP isn't in them
    (private/reserved ranges, or genuinely unknown addresses)."""

    name = "geoip_mmdb"

    def __init__(self, cfg: TIConfig) -> None:
        pass

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        city_reader, asn_reader = _get_readers()
        if city_reader is None and asn_reader is None:
            return {"status": "fail", "message": f"no .mmdb files found under {_GEOIP_DIR}"}

        country = city = isp = ""
        found = False

        if city_reader is not None:
            try:
                resp = city_reader.city(ip)
                country = resp.country.name or ""
                city = resp.city.name or ""
                found = True
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass

        if asn_reader is not None:
            try:
                resp = asn_reader.asn(ip)
                isp = resp.autonomous_system_organization or ""
                found = True
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass

        if not found:
            return {"status": "fail", "message": "address not found in GeoLite2 database (likely private/reserved)"}
        return {"status": "success", "country": country, "city": city, "isp": isp}

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return {"skipped": True}

    async def lookup_url(self, url: str) -> dict[str, Any]:
        return {"skipped": True}

    async def lookup_hash(self, h: str) -> dict[str, Any]:
        return {"skipped": True}
