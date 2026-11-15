"""Which vulnerability to patch first. Pure functions, shared by the worker
(vuln_scan.py) and server-api (routes/vulnerabilities.py).

Order: exploited in the wild (CISA KEV) before likely to be exploited (FIRST
EPSS) before merely severe (CVSS). A critical CVSS score with a tiny EPSS is
a theoretical risk; a medium one on the KEV list is being used today."""
from __future__ import annotations

import math

PRIORITIES = ("critical", "high", "medium", "low")
EPSS_HIGH = 0.10      # top ~2% of all CVEs
EPSS_MEDIUM = 0.01
SEVERITY_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base(vector: str | None) -> float | None:
    """Base score of a CVSS 3.0/3.1 vector; None for anything else."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(total, 10))


def severity_of(score: float | None) -> str | None:
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else None


def priority(kev: bool, epss: float | None, cvss: float | None, severity: str | None) -> tuple[str, float]:
    """(tier, sort score). Tiers: critical = on the KEV list; high = EPSS ≥ 10%
    or CVSS ≥ 9 with EPSS ≥ 1%; medium = CVSS ≥ 7, EPSS ≥ 1% or a critical/high
    vendor rating; low = the rest."""
    epss = epss or 0.0
    base = cvss if cvss is not None else SEVERITY_SCORE.get((severity or "").lower(), 0.0)
    score = (1000 if kev else 0) + epss * 500 + base * 10
    if kev:
        return "critical", score
    if epss >= EPSS_HIGH or (base >= 9 and epss >= EPSS_MEDIUM):
        return "high", score
    if base >= 7 or epss >= EPSS_MEDIUM or (severity or "").lower() in ("critical", "high"):
        return "medium", score
    return "low", score
