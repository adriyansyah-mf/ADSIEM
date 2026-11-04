# tests/server-api/test_soc_command.py
"""Shaping logic behind /api/metrics/soc/geo and /soc/posture."""
from datetime import datetime, timedelta, timezone

from app.services import soc_command
from app.services.soc_command import aggregate_geo, backlog_aging, hq_target, worst_severity

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)

_LOC = {
    "203.0.113.9": {"lat": 55.75, "lon": 37.62, "city": "Moscow", "country": "Russia", "country_code": "RU"},
    "198.51.100.4": {"lat": 55.0, "lon": 37.0, "city": None, "country": "Russia", "country_code": "RU"},
    "192.0.2.77": {"lat": 39.9, "lon": 116.4, "city": "Beijing", "country": "China", "country_code": "CN"},
}


def test_worst_severity_orders_critical_first_and_tolerates_unknown():
    assert worst_severity(["low", "critical", "medium"]) == "critical"
    assert worst_severity(["bogus", "low"]) == "low"
    assert worst_severity([]) == "info"


def test_aggregate_geo_merges_severities_per_ip_and_rolls_up_countries():
    rows = [
        ("203.0.113.9", "high", 5, NOW - timedelta(hours=2)),
        ("203.0.113.9", "critical", 1, NOW - timedelta(hours=1)),
        ("198.51.100.4", "low", 3, NOW),
        ("192.0.2.77", "medium", 10, NOW),
        ("10.0.0.5", "high", 7, NOW),  # private: never geolocates
    ]
    geo = aggregate_geo(rows, _LOC.get)

    first = geo["points"][0]
    assert first["ip"] == "203.0.113.9"  # critical sorts ahead of higher-volume medium
    assert first["count"] == 6 and first["by_severity"] == {"high": 5, "critical": 1}
    assert first["max_severity"] == "critical"
    assert first["last_seen"] == (NOW - timedelta(hours=1)).isoformat()

    ru = next(c for c in geo["countries"] if c["country_code"] == "RU")
    assert ru == {"country": "Russia", "country_code": "RU", "count": 9, "unique_ips": 2,
                  "by_severity": {"high": 5, "critical": 1, "low": 3}, "max_severity": "critical"}
    assert [c["country_code"] for c in geo["countries"]] == ["CN", "RU"]  # by volume

    assert geo["located_alerts"] == 19
    assert geo["unlocated_alerts"] == 7 and geo["unlocated_ips"] == 1


def test_aggregate_geo_truncates_points_but_keeps_country_totals():
    rows = [(ip, "low", 1, None) for ip in _LOC]
    geo = aggregate_geo(rows, _LOC.get, max_points=1)
    assert len(geo["points"]) == 1 and geo["points_truncated"] is True
    assert sum(c["count"] for c in geo["countries"]) == 3
    assert geo["points"][0]["last_seen"] is None


def test_backlog_aging_buckets_and_sla_breaches_only_for_unacknowledged():
    sla = {"critical": 15, "high": 60, "medium": 240, "low": 1440}
    alerts = [
        ("critical", "new", NOW - timedelta(minutes=20), False),     # breach
        ("critical", "in_progress", NOW - timedelta(hours=3), True),  # acknowledged: no breach
        ("high", "new", NOW - timedelta(minutes=30), True),          # within SLA
        ("medium", "new", NOW - timedelta(hours=30), False),         # breach, >24h
        ("info", "new", NOW - timedelta(days=3), False),             # info has no SLA
        ("weird", "new", NOW - timedelta(minutes=5), False),         # unknown severity counts as info
        ("low", "new", None, False),                                 # no timestamp: skipped
    ]
    out = backlog_aging(alerts, NOW, sla)
    assert out["open_total"] == 6 and out["unassigned"] == 4
    buckets = {b["bucket"]: b for b in out["age_buckets"]}
    assert buckets["lt_1h"]["critical"] == 1 and buckets["lt_1h"]["high"] == 1 and buckets["lt_1h"]["info"] == 1
    assert buckets["1h_4h"]["critical"] == 1
    assert buckets["gt_24h"]["medium"] == 1 and buckets["gt_24h"]["info"] == 1
    assert out["sla_breaches"] == {"critical": 1, "high": 0, "medium": 1, "low": 0}
    assert out["sla_breaches_total"] == 2
    assert out["oldest_new_minutes"]["critical"] == 20.0


def test_sla_minutes_env_override_and_bad_values(monkeypatch):
    monkeypatch.setenv("SOC_SLA_CRITICAL_MINUTES", "5")
    monkeypatch.setenv("SOC_SLA_HIGH_MINUTES", "soon")
    sla = soc_command.sla_minutes()
    assert sla["critical"] == 5 and sla["high"] == 60


def test_hq_target_requires_valid_coordinates(monkeypatch):
    monkeypatch.delenv("SOC_HQ_LAT", raising=False)
    monkeypatch.delenv("SOC_HQ_LON", raising=False)
    assert hq_target() is None
    monkeypatch.setenv("SOC_HQ_LAT", "-6.2")
    monkeypatch.setenv("SOC_HQ_LON", "106.8")
    assert hq_target() == {"lat": -6.2, "lon": 106.8, "label": "Protected site"}
    monkeypatch.setenv("SOC_HQ_LABEL", "Jakarta DC")
    assert hq_target()["label"] == "Jakarta DC"
    monkeypatch.setenv("SOC_HQ_LAT", "123")
    assert hq_target() is None
