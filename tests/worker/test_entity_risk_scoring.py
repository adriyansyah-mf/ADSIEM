# tests/worker/test_entity_risk_scoring.py
"""Unified host/user risk (worker/worker/entity_risk.py): points, tactic
bonus, decay, cap, risk-alert conditions, source/tactic/entity extraction."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker import entity_risk as er  # noqa: E402

T0 = 1_800_000_000.0
DAY = 86400


def entry(source="sigma"):
    return {"alert_id": "a", "title": "t", "severity": "high", "source": source, "tactics": [], "at": "x"}


def test_points_tactic_bonus_and_cap():
    s, added = er.apply({}, points=30, tactics=["execution"], entry=entry(), now=T0)
    assert added == 40 and s["risk_score"] == 40 and s["alert_count"] == 1 and s["recent"][0]["points"] == 40
    # the same tactic again within a day: no bonus
    s, added = er.apply(s, points=30, tactics=["execution"], entry=entry(), now=T0 + 60)
    assert added == 30 and 69 < s["risk_score"] <= 70
    # a new tactic adds its bonus; the score never passes 100
    s, added = er.apply(s, points=50, tactics=["command_and_control", "exfiltration"], entry=entry("ioc"), now=T0 + 120)
    assert added == 70 and s["risk_score"] == 100 and s["peak_score"] == 100
    assert s["sources"] == {"sigma": 2, "ioc": 1} and er.active_tactics(s, T0 + 120) == [
        "command_and_control", "execution", "exfiltration"]


def test_decay_halves_a_day_later_and_old_tactics_expire():
    s, _ = er.apply({}, points=50, tactics=["execution"], entry=entry(), now=T0)
    s2, added = er.apply(s, points=0, tactics=["execution"], entry=entry(), now=T0 + DAY + 1)
    assert added == 10  # a day later the tactic counts as new again
    assert abs(s2["risk_score"] - 40) < 0.1   # 60 halved (30) plus the 10 bonus
    assert er.decayed(80, DAY) == 40 and er.decayed(80, 0) == 80


def test_risk_alert_needs_threshold_two_tactics_and_a_day_between():
    one_tactic, _ = er.apply({"risk_score": 90, "updated": T0}, points=30, tactics=["execution"], entry=entry(), now=T0)
    assert not er.wants_risk_alert(one_tactic, None, 70, T0)
    two, _ = er.apply(one_tactic, points=5, tactics=["persistence"], entry=entry(), now=T0)
    assert er.wants_risk_alert(two, None, 70, T0)
    assert not er.wants_risk_alert(two, T0 - 3600, 70, T0)          # raised an hour ago
    assert er.wants_risk_alert(two, T0 - DAY, 70, T0)
    low, _ = er.apply({}, points=15, tactics=["execution", "persistence"], entry=entry(), now=T0)
    assert low["risk_score"] == 35 and not er.wants_risk_alert(low, None, 70, T0)


def test_source_tactics_and_entities():
    assert er.source_of({"id": "ueba-host"}) == "ueba"
    assert er.source_of({"id": "rule-ioa-webserver-shell"}) == "ioa"
    assert er.source_of({"id": "rule-ioc-ip-match-blocked"}) == "ioc"
    assert er.source_of({"id": "rule-behavior-beaconing"}) == "behavior"
    assert er.source_of({"id": "rule-siem-agent-sensor-silent"}) == "agent_tamper"
    assert er.source_of({"id": "6f1c…uuid"}) == "sigma"
    assert er.tactics_of({"tags": ["attack.execution", "attack.t1059"],
                          "mitre_tags": ["attack.execution", "attack.command-and-control"]}, []) == [
        "execution", "command_and_control"]
    # UEBA alerts carry techniques only: the kill-chain stage stands in
    assert er.tactics_of({"mitre_tags": ["attack.t1110"]}, ["T1110"]) == ["credential_access"]
    assert er.entities_of("web-01", None, {"matched_fields": {"user.name": "alice"}}) == [
        ("host", "web-01"), ("user", "alice")]
    assert er.entities_of(None, "-", {}) == []
