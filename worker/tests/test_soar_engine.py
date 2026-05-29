import pytest
from worker.soar_engine import _matches_trigger

def _alert(severity="high", rule_title="SQL Injection", source_ip="1.2.3.4",
           hostname="web01", user_name=None, tags=None, mitre_tags=None):
    return {
        "severity": severity,
        "rule_title": rule_title,
        "source_ip": source_ip,
        "hostname": hostname,
        "user_name": user_name,
        "tags": tags if tags is not None else ["attack.initial_access", "attack.t1190"],
        "mitre_tags": mitre_tags if mitre_tags is not None else ["attack.t1190"],
    }

def test_match_all_passes():
    trigger = {
        "match": "all",
        "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            {"field": "rule_title", "operator": "contains", "value": "SQL"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is True

def test_match_all_fails_one():
    trigger = {
        "match": "all",
        "conditions": [
            {"field": "severity", "operator": "in", "value": ["high", "critical"]},
            {"field": "rule_title", "operator": "contains", "value": "Brute Force"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is False

def test_match_any_passes():
    trigger = {
        "match": "any",
        "conditions": [
            {"field": "severity", "operator": "eq", "value": "low"},
            {"field": "rule_title", "operator": "contains", "value": "SQL"},
        ]
    }
    assert _matches_trigger(trigger, _alert()) is True

def test_eq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "eq", "value": "high"}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(severity="low")) is False

def test_neq_operator():
    trigger = {"match": "all", "conditions": [{"field": "severity", "operator": "neq", "value": "low"}]}
    assert _matches_trigger(trigger, _alert()) is True

def test_not_null_operator():
    trigger = {"match": "all", "conditions": [{"field": "source_ip", "operator": "not_null", "value": None}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(source_ip=None)) is False

def test_tags_contains():
    trigger = {"match": "all", "conditions": [{"field": "tags", "operator": "contains", "value": "attack.t1190"}]}
    assert _matches_trigger(trigger, _alert()) is True
    assert _matches_trigger(trigger, _alert(tags=[])) is False

def test_empty_conditions_matches():
    trigger = {"match": "all", "conditions": []}
    assert _matches_trigger(trigger, _alert()) is True
