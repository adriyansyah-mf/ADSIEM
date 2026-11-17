"""Phishing domain model in the event pipeline.

enrich() scores the host name of a DNS query or web event with the lexical
model (model.py) and writes phishing.score, phishing.domain and, above a
threshold, phishing.verdict (medium: 1 in 10,000 benign names score that
high on held-out data; high: 1 in 100,000) into the decoded event. Sigma
rules (rules/phishing_domain_ml_*.yaml) alert on the verdict, and the fields
are indexed with the event for hunting.

Registered domains on the popular list (assets/popular_domains.txt.gz, Tranco
top) never get a verdict: phishing pages on a big platform cannot be told
from its host name, and those names are most of the traffic.
"""
from __future__ import annotations

import gzip
from functools import lru_cache
from pathlib import Path

from . import features as F
from . import model as M

NAME_FIELDS = ("dns.question.name", "url.domain", "destination.domain")
POPULAR_PATH = Path(__file__).parent / "assets" / "popular_domains.txt.gz"


@lru_cache(maxsize=1)
def popular() -> frozenset[str]:
    try:
        with gzip.open(POPULAR_PATH, "rt", encoding="utf-8") as f:
            return frozenset(s for s in (line.strip() for line in f) if s and not s.startswith("#"))
    except OSError:
        return frozenset()


def verdict(model: M.Model, score: float) -> str | None:
    high = model.thresholds.get("fpr_1e-05")
    medium = model.thresholds.get("fpr_0.0001")
    if high is not None and score >= high:
        return "high"
    if medium is not None and score >= medium:
        return "medium"
    return None


def enrich(decoded: dict, model: M.Model | None = None) -> str | None:
    """Score the event's host name in place; returns the verdict, if any."""
    m = model or M.default()
    if m is None:
        return None
    for field in NAME_FIELDS:
        name = decoded.get(field)
        if not isinstance(name, str) or not name:
            continue
        score = m.score(name)
        if score is None:
            continue
        name = F.normalize(name)
        decoded["phishing.score"] = round(score, 4)
        decoded["phishing.domain"] = name
        regdom = F.registered_domain(name)
        decoded["phishing.registered_domain"] = regdom
        if regdom in popular():
            return None
        v = verdict(m, score)
        if v:
            decoded["phishing.verdict"] = v
        return v
    return None
