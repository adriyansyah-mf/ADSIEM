# tests/server-api/test_agent_tamper.py
"""Heartbeat integrity: baseline on first report and on upgrade, one event per change."""
from types import SimpleNamespace

from app.services.agent_tamper import check_integrity

A, B, C = "a" * 64, "b" * 64, "c" * 64


def _agent(binary=None, config=None, version=None):
    return SimpleNamespace(binary_sha256=binary, config_sha256=config, integrity_version=version)


def test_first_report_sets_the_baseline_silently():
    updates, events = check_integrity(_agent(), "1.7.0", {"binary_sha256": A, "config_sha256": B})
    assert updates == {"binary_sha256": A, "config_sha256": B, "integrity_version": "1.7.0"}
    assert events == []


def test_an_upgrade_rebaselines_silently():
    updates, events = check_integrity(_agent(A, B, "1.6.0"), "1.7.0", {"binary_sha256": C, "config_sha256": B})
    assert updates["binary_sha256"] == C and updates["integrity_version"] == "1.7.0" and events == []


def test_a_changed_binary_or_config_is_one_event_each():
    updates, events = check_integrity(_agent(A, B, "1.7.0"), "1.7.0", {"binary_sha256": C, "config_sha256": C})
    assert updates == {"binary_sha256": C, "config_sha256": C}
    assert events == [
        {"file": "binary", "previous": A, "current": C, "version": "1.7.0"},
        {"file": "config", "previous": B, "current": C, "version": "1.7.0"},
    ]


def test_nothing_reported_or_unchanged_or_unreadable_is_no_event():
    assert check_integrity(_agent(A, B, "1.7.0"), "1.7.0", None) == ({}, [])
    assert check_integrity(_agent(A, B, "1.7.0"), "1.7.0", {"binary_sha256": A, "config_sha256": B}) == ({}, [])
    assert check_integrity(_agent(A, B, "1.7.0"), "1.7.0", {"binary_sha256": A, "config_sha256": ""}) == ({}, [])
