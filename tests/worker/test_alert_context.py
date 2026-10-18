# tests/worker/test_alert_context.py
"""What an alert records about why it fired."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

from worker.alert_manager import alert_context, mitre_from_tags
from worker.sigma_engine import SigmaEngine

RULE = """
title: Brute force
id: rule-bf
detection:
  s:
    event.action: login_failed
  condition: s
threshold:
  count: 2
  timewindow: 60
  group_by: source.ip
level: high
tags: [attack.credential_access, attack.t1110, attack.t1110.001]
"""


def test_mitre_from_sigma_tags():
    assert mitre_from_tags(["attack.credential_access", "attack.t1110", "attack.T1110.001", "attack.t1110"]) \
        == ["T1110", "T1110.001"]
    assert mitre_from_tags(["ueba", "attack.tactic"]) == []


def test_matches_carry_the_db_rule_id_and_threshold_context():
    e = SigmaEngine()
    e.load_from_yaml_list([RULE], ["4b1c2c4e-0000-4000-8000-000000000001"])
    ev = {"event.action": "login_failed", "source.ip": "9.9.9.9"}
    asyncio.run(e.evaluate(ev))
    [match] = asyncio.run(e.evaluate(ev))
    assert match["rule_db_id"] == "4b1c2c4e-0000-4000-8000-000000000001"
    ctx = alert_context(match)
    assert ctx["rule_ref"] == "rule-bf"
    assert ctx["correlation_hit_count"] == 2 and ctx["correlation_window"] == 60
    assert ctx["correlation_group"] == "9.9.9.9" and ctx["correlation_group_by"] == "source.ip"
    assert ctx["tags"] == ["attack.credential_access", "attack.t1110", "attack.t1110.001"]


def test_context_keeps_ueba_reasons_and_drops_empty_values():
    ctx = alert_context({"id": "ueba-ip", "title": "t", "level": "high", "tags": [], "mitre_tags": [],
                         "matched_fields": {"ueba_reasons": ["usernames 47 vs typical 1"]}})
    assert ctx == {"rule_ref": "ueba-ip", "matched_fields": {"ueba_reasons": ["usernames 47 vs typical 1"]}}


def test_rules_loaded_without_ids_still_work():
    e = SigmaEngine()
    e.load_from_yaml_list([RULE.replace("threshold:\n  count: 2\n  timewindow: 60\n  group_by: source.ip\n", "")])
    [match] = asyncio.run(e.evaluate({"event.action": "login_failed"}))
    assert match["rule_db_id"] is None
