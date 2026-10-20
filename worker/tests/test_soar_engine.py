"""Trigger matching keeps the old playbook semantics (bare field names resolve against the alert)."""
from worker.soar.conditions import matches


def _ctx(severity="high", rule_title="SQL Injection", source_ip="1.2.3.4",
         hostname="web01", user_name=None, tags=None, mitre_tags=None):
    return {"trigger": {
        "severity": severity,
        "rule_title": rule_title,
        "source_ip": source_ip,
        "hostname": hostname,
        "user_name": user_name,
        "tags": tags if tags is not None else ["attack.initial_access", "attack.t1190"],
        "mitre_tags": mitre_tags if mitre_tags is not None else ["attack.t1190"],
    }, "steps": {}}


def test_match_all_passes():
    trigger = {"match": "all", "conditions": [
        {"field": "severity", "operator": "eq", "value": "high"},
        {"field": "rule_title", "operator": "contains", "value": "SQL"},
    ]}
    assert matches(trigger, _ctx()) is True


def test_match_all_fails_one():
    trigger = {"match": "all", "conditions": [
        {"field": "severity", "operator": "eq", "value": "high"},
        {"field": "rule_title", "operator": "contains", "value": "XSS"},
    ]}
    assert matches(trigger, _ctx()) is False


def test_match_any_passes():
    trigger = {"match": "any", "conditions": [
        {"field": "severity", "operator": "eq", "value": "critical"},
        {"field": "rule_title", "operator": "contains", "value": "SQL"},
    ]}
    assert matches(trigger, _ctx()) is True


def test_eq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "eq", "value": "high"}]}
    assert matches(trigger, _ctx()) is True
    assert matches(trigger, _ctx(severity="low")) is False


def test_neq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "neq", "value": "low"}]}
    assert matches(trigger, _ctx()) is True


def test_not_null_operator():
    trigger = {"match": "all", "conditions": [{"field": "source_ip", "operator": "not_null"}]}
    assert matches(trigger, _ctx()) is True
    assert matches(trigger, _ctx(source_ip=None)) is False


def test_tags_contains():
    trigger = {"match": "all", "conditions": [{"field": "tags", "operator": "contains", "value": "attack.t1190"}]}
    assert matches(trigger, _ctx()) is True
    assert matches(trigger, _ctx(tags=[])) is False


def test_empty_conditions_matches():
    assert matches({"match": "all", "conditions": []}, _ctx()) is True
