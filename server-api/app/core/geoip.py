# server-api/app/core/geoip.py
"""Local MaxMind GeoLite2 (.mmdb) country lookup — no external API call,
no rate limit. Mirrors worker/worker/ti/providers/geoip.py's approach."""
from __future__ import annotations
import functools
import os
import threading

import geoip2.database
import geoip2.errors

_GEOIP_DIR = os.environ.get("GEOIP_DIR", "/app/mmdb")

_lock = threading.Lock()
_city_reader: geoip2.database.Reader | None = None
_load_attempted = False


def _get_reader() -> geoip2.database.Reader | None:
    global _city_reader, _load_attempted
    with _lock:
        if _load_attempted:
            return _city_reader
        _load_attempted = True
        path = os.path.join(_GEOIP_DIR, "GeoLite2-City.mmdb")
        if os.path.exists(path):
            _city_reader = geoip2.database.Reader(path)
        return _city_reader


def lookup_country(ip: str | None) -> str | None:
    """Returns the full country name (e.g. "United States") for an IP, or
    None if the IP is missing, private/reserved, or the .mmdb isn't mounted."""
    if not ip:
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        return reader.city(ip).country.name
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None


def geoip_available() -> bool:
    """True when the GeoLite2-City database is mounted and readable."""
    return _get_reader() is not None


@functools.lru_cache(maxsize=8192)
def lookup_location(ip: str | None) -> dict | None:
    """Country, city and coordinates for the attack map, or None when the IP is
    missing, private/reserved, has no coordinates, or the .mmdb isn't mounted.
    Cached because the dashboard asks for the same attacker IPs on every refresh;
    callers must not mutate the returned dict."""
    if not ip:
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        rec = reader.city(ip)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None
    lat, lon = rec.location.latitude, rec.location.longitude
    if lat is None or lon is None:
        return None
    return {
        "lat": round(float(lat), 4),
        "lon": round(float(lon), 4),
        "city": rec.city.name,
        "country": rec.country.name,
        "country_code": rec.country.iso_code,
    }
