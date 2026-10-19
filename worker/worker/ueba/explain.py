# worker/worker/ueba/explain.py
"""Why an entity is anomalous, and how much risk that adds.

The IsolationForest says *that* a feature vector is unusual; this module says
*why*. Baselines are robust (median + IQR-based scale, p95) so a handful of
attack hours in the training window don't move them much. An entity is compared
with its own history when it has enough snapshots, otherwise with the whole
population. Reasons map to MITRE ATT&CK techniques for the alert and timeline.
"""
import math
from typing import Iterable

import numpy as np

MIN_ENTITY_SNAPSHOTS = 12   # hours of history before an entity's own baseline is used
Z_THRESHOLD = 3.0           # robust z-score that counts as "far from normal"
RARE_HOUR_FRACTION = 0.02   # an hour seen in <2% of baseline activity is unusual
RISK_HALF_LIFE = 6 * 3600   # risk halves every 6h without new anomalies
MAX_REASONS = 4
MIN_RATIO_EVENTS = 10       # a ratio over fewer events (1 failure of 1) means nothing
MIN_HOURS_FOR_TIME = 20     # distinct active hours a baseline needs before "rare hour" means anything

# How busy an entity is, and when — shown as context, never an anomaly on its
# own: a popular web client or a night-shift admin is not an attack. Anomalies
# need a security-relevant deviation (failures, many users/hosts, sudo, new IP).
CONTEXT_FEATURES = {"total_events", "login_count", "hour_of_day", "is_weekend"}

# Smallest count that can be suspicious at all, whatever the baseline says.
_MIN_VALUE = {
    "unique_users": 3, "failed_count": 5, "unique_target_hosts": 3,
    "sudo_count": 3, "unique_ips": 3, "unique_hosts": 3,
}

# Features where only a *higher* value is suspicious (a quiet hour is not an attack).
_UPWARD = {
    "login_count", "failed_ratio", "unique_ips", "unique_hosts", "sudo_count",
    "unique_users", "total_events", "unique_target_hosts", "failed_count",
}

# feature -> (technique id, name) per entity type
_MITRE = {
    "user": {
        "failed_ratio": ("T1110", "Brute Force"),
        "new_ip_seen": ("T1078", "Valid Accounts"),
        "unique_ips": ("T1078", "Valid Accounts"),
        "sudo_count": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
        "unique_hosts": ("T1021", "Remote Services"),
        "hour_of_day": ("T1078", "Valid Accounts"),
    },
    "ip": {
        "failed_ratio": ("T1110", "Brute Force"),
        "failed_count": ("T1110", "Brute Force"),
        "unique_users": ("T1110.003", "Brute Force: Password Spraying"),
        "unique_target_hosts": ("T1021", "Remote Services"),
        "total_events": ("T1595", "Active Scanning"),
    },
}

_LABELS = {
    "login_count": "events in the last hour",
    "failed_ratio": "failure ratio",
    "unique_ips": "distinct source IPs",
    "unique_hosts": "distinct hosts",
    "sudo_count": "sudo/privilege events",
    "unique_users": "distinct usernames tried",
    "total_events": "events in the last hour",
    "unique_target_hosts": "distinct target hosts",
    "failed_count": "failed attempts",
}


def _scale(values: np.ndarray, median: float) -> float:
    q1, q3 = np.percentile(values, [25, 75])
    scale = (q3 - q1) / 1.349  # IQR → std for a normal distribution
    # floors keep a constant baseline (IQR 0) from making every change "infinite"
    return float(max(scale, 0.1 * abs(median), 0.05 if median < 1 else 1.0))


def build_baseline(vectors: Iterable[dict], keys: list[str]) -> dict:
    rows = list(vectors)
    if not rows:
        return {}
    baseline: dict[str, dict] = {}
    for key in keys:
        col = np.array([float(r.get(key, 0.0)) for r in rows])
        if key == "hour_of_day":
            hours = np.bincount(np.clip(col.astype(int), 0, 23), minlength=24)
            baseline[key] = {"freq": (hours / hours.sum()).round(4).tolist(),
                             "hours_seen": int((hours > 0).sum())}
            continue
        median = float(np.median(col))
        baseline[key] = {
            "median": round(median, 4),
            "scale": round(_scale(col, median), 4),
            "p95": round(float(np.percentile(col, 95)), 4),
        }
    baseline["_n"] = len(rows)
    return baseline


def _fmt(v: float) -> str:
    return f"{v:.2f}" if abs(v) < 10 and v != int(v) else f"{v:.0f}"


def explain(entity_type: str, features: dict, entity_profile: dict | None, population: dict) -> list[dict]:
    """Ranked reasons this feature vector is unusual (most severe first)."""
    use_entity = bool(entity_profile) and entity_profile.get("_n", 0) >= MIN_ENTITY_SNAPSHOTS
    base = entity_profile if use_entity else population
    scope = "its own baseline" if use_entity else "all entities"
    reasons = []

    for key, value in features.items():
        value = float(value)
        stats = (base or {}).get(key) or (population or {}).get(key)
        if not stats:
            continue

        if key == "hour_of_day":
            freq = stats.get("freq") or []
            hour = int(value) % 24
            # a baseline only a few hours old makes every other hour look rare
            if stats.get("hours_seen", 0) >= MIN_HOURS_FOR_TIME and len(freq) == 24 \
                    and freq[hour] < RARE_HOUR_FRACTION:
                reasons.append({
                    "feature": key, "value": value, "z": round((RARE_HOUR_FRACTION - freq[hour]) * 100, 2),
                    "text": f"active at {hour:02d}:00 UTC, an hour that accounts for "
                            f"{freq[hour] * 100:.1f}% of {scope}",
                })
            continue
        if key == "new_ip_seen":
            if value >= 1 and stats.get("median", 0) < 0.5:
                reasons.append({"feature": key, "value": value, "z": Z_THRESHOLD,
                                "text": "signed in from an IP never seen for this user in 7 days"})
            continue
        if key == "is_weekend":
            continue
        if key == "failed_ratio" and float(features.get("total_events", features.get("login_count", 0))) < MIN_RATIO_EVENTS:
            continue

        median, scale = float(stats.get("median", 0.0)), float(stats.get("scale", 1.0)) or 1.0
        z = (value - median) / scale
        if key in _UPWARD and z < 0:
            continue
        # most IPs are web clients that never log in, so one login is "infinitely"
        # above a baseline of 0; a count has to reach a meaningful size first
        if value < _MIN_VALUE.get(key, 0):
            continue
        if abs(z) >= Z_THRESHOLD and value > float(stats.get("p95", median)):
            label = _LABELS.get(key, key)
            reasons.append({
                "feature": key, "value": value, "z": round(z, 2),
                "text": f"{label} {_fmt(value)} vs typical {_fmt(median)} "
                        f"(p95 {_fmt(float(stats.get('p95', median)))}, {scope})",
            })

    reasons.sort(key=lambda r: abs(r["z"]), reverse=True)
    return reasons[:MAX_REASONS]


def mitre_for(entity_type: str, reasons: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in security_reasons(reasons):
        technique = _MITRE.get(entity_type, {}).get(r["feature"])
        if technique and technique[0] not in seen:
            seen.add(technique[0])
            out.append({"id": technique[0], "name": technique[1]})
    return out


def decayed_risk(risk: float, seconds_since: float) -> float:
    if seconds_since <= 0:
        return risk
    return risk * math.pow(0.5, seconds_since / RISK_HALF_LIFE)


def anomaly_strength(score: float, threshold: float) -> float:
    """0..1 — how far below the anomaly threshold an IsolationForest score is.
    Normal scores (>= threshold) give 0, so they never raise risk."""
    if score >= threshold:
        return 0.0
    return min((threshold - score) / 0.15, 1.0)


def security_reasons(reasons: list[dict]) -> list[dict]:
    return [r for r in reasons if r["feature"] not in CONTEXT_FEATURES]


def deviation_strength(reasons: list[dict]) -> float:
    """0..1 from the largest robust z-score among security-relevant reasons.
    IsolationForest saturates outside its training range (60 tried usernames
    scores like 3), so a large deviation has to count on its own: z=3 → 0,
    z>=10 → 1."""
    reasons = security_reasons(reasons)
    if not reasons:
        return 0.0
    return min(max((max(abs(r["z"]) for r in reasons) - Z_THRESHOLD) / 7.0, 0.0), 1.0)


def assess(if_score: float, if_threshold: float, reasons: list[dict]) -> float:
    """Anomaly strength (0 = normal). Requires a security-relevant explanation:
    an IsolationForest outlier with nothing deviating — or only volume/timing
    deviating — is noise, while a strong explained deviation counts even when
    the forest misses it."""
    if not security_reasons(reasons):
        return 0.0
    forest = anomaly_strength(if_score, if_threshold)
    deviation = deviation_strength(reasons)
    if forest == 0.0 and deviation < 0.3:
        return 0.0
    return max(forest, deviation)


def next_risk(old_risk: float, seconds_since: float, strength: float) -> float:
    """Risk decays with time; each anomaly closes part of the gap to 100."""
    base = decayed_risk(old_risk, seconds_since)
    if strength <= 0:
        return round(base, 2)
    return round(base + (100.0 - base) * (0.15 + 0.55 * strength), 2)
