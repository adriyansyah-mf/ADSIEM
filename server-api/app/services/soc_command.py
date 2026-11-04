# server-api/app/services/soc_command.py
"""Pure aggregation for the SOC command-center dashboard: attack-origin geo
rollups, triage backlog aging and acknowledgment-SLA breaches.

Kept free of DB/GeoIP I/O so the shaping logic is unit-testable; the route in
app/api/routes/metrics.py feeds it query rows and a `locate(ip)` callable."""
from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from datetime import datetime

SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Minutes an alert may sit unacknowledged before it breaches the triage SLA.
# Override per deployment with SOC_SLA_<SEVERITY>_MINUTES.
_DEFAULT_SLA_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440}

AGE_BUCKETS = (("lt_1h", 60), ("1h_4h", 240), ("4h_24h", 1440), ("gt_24h", None))


def worst_severity(severities: Iterable[str]) -> str:
    return min(severities, key=lambda s: _RANK.get(s, len(SEVERITIES)), default="info")


def sla_minutes() -> dict[str, int]:
    out = {}
    for sev, default in _DEFAULT_SLA_MINUTES.items():
        raw = os.environ.get(f"SOC_SLA_{sev.upper()}_MINUTES")
        try:
            out[sev] = int(raw) if raw else default
        except ValueError:
            out[sev] = default
    return out


def hq_target() -> dict | None:
    """Where attack arcs land on the map: the defended site, set with
    SOC_HQ_LAT / SOC_HQ_LON (and optional SOC_HQ_LABEL). None hides the arcs."""
    try:
        lat = float(os.environ["SOC_HQ_LAT"])
        lon = float(os.environ["SOC_HQ_LON"])
    except (KeyError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return {"lat": lat, "lon": lon, "label": os.environ.get("SOC_HQ_LABEL") or "Protected site"}


def aggregate_geo(
    rows: Iterable[tuple[str, str, int, datetime | None]],
    locate: Callable[[str], dict | None],
    max_points: int = 300,
) -> dict:
    """Roll (source_ip, severity, alert_count, last_seen) rows into map points
    (one per geolocated IP) and per-country totals. IPs that don't geolocate
    (RFC1918, loopback, unknown) are counted separately as internal/unknown so
    the map never silently drops volume."""
    by_ip: dict[str, dict] = {}
    for ip, severity, count, last_seen in rows:
        if not ip:
            continue
        slot = by_ip.setdefault(ip, {"ip": ip, "count": 0, "by_severity": {}, "last_seen": None})
        slot["count"] += count
        slot["by_severity"][severity] = slot["by_severity"].get(severity, 0) + count
        if last_seen and (slot["last_seen"] is None or last_seen > slot["last_seen"]):
            slot["last_seen"] = last_seen

    points: list[dict] = []
    countries: dict[str, dict] = {}
    unlocated_alerts = unlocated_ips = 0
    for slot in by_ip.values():
        loc = locate(slot["ip"])
        if not loc:
            unlocated_alerts += slot["count"]
            unlocated_ips += 1
            continue
        point = {
            **slot,
            **loc,
            "max_severity": worst_severity(slot["by_severity"]),
            "last_seen": slot["last_seen"].isoformat() if slot["last_seen"] else None,
        }
        points.append(point)
        key = loc.get("country_code") or loc.get("country") or "??"
        c = countries.setdefault(key, {
            "country": loc.get("country") or "Unknown", "country_code": loc.get("country_code"),
            "count": 0, "unique_ips": 0, "by_severity": {},
        })
        c["count"] += slot["count"]
        c["unique_ips"] += 1
        for sev, n in slot["by_severity"].items():
            c["by_severity"][sev] = c["by_severity"].get(sev, 0) + n

    points.sort(key=lambda p: (_RANK.get(p["max_severity"], 9), -p["count"]))
    country_list = sorted(countries.values(), key=lambda c: -c["count"])
    for c in country_list:
        c["max_severity"] = worst_severity(c["by_severity"])
    return {
        "points": points[:max_points],
        "points_truncated": len(points) > max_points,
        "countries": country_list,
        "located_alerts": sum(p["count"] for p in points),
        "unlocated_alerts": unlocated_alerts,
        "unlocated_ips": unlocated_ips,
    }


def _age_bucket(minutes: float) -> str:
    for name, upper in AGE_BUCKETS:
        if upper is None or minutes < upper:
            return name
    return AGE_BUCKETS[-1][0]


def backlog_aging(
    open_alerts: Iterable[tuple[str, str, datetime | None, bool]],
    now: datetime,
    sla: dict[str, int] | None = None,
) -> dict:
    """Shape open alerts (severity, status, created_at, is_assigned) into an
    age × severity matrix plus SLA breaches. Only `status == "new"` alerts can
    breach: anything already in progress has been acknowledged."""
    sla = sla if sla is not None else sla_minutes()
    matrix = {name: {s: 0 for s in SEVERITIES} for name, _ in AGE_BUCKETS}
    breaches = {s: 0 for s in sla}
    oldest_new: dict[str, float] = {}
    total = unassigned = 0
    for severity, status, created_at, assigned in open_alerts:
        if created_at is None:
            continue
        total += 1
        if not assigned:
            unassigned += 1
        age = max((now - created_at).total_seconds() / 60, 0.0)
        sev = severity if severity in _RANK else "info"
        matrix[_age_bucket(age)][sev] += 1
        if status == "new":
            if sev not in oldest_new or age > oldest_new[sev]:
                oldest_new[sev] = age
            limit = sla.get(sev)
            if limit is not None and age > limit:
                breaches[sev] += 1
    return {
        "open_total": total,
        "unassigned": unassigned,
        "age_buckets": [{"bucket": name, **matrix[name]} for name, _ in AGE_BUCKETS],
        "sla_minutes": sla,
        "sla_breaches": breaches,
        "sla_breaches_total": sum(breaches.values()),
        "oldest_new_minutes": {k: round(v, 1) for k, v in oldest_new.items()},
    }
