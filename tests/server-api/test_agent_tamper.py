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


def test_uninstall_token_is_stable_per_agent_and_only_its_hash_leaves():
    import hashlib

    from app.services.agent_tamper import uninstall_token, uninstall_token_sha256

    t1, t2 = uninstall_token("agent-1"), uninstall_token("agent-2")
    assert t1 == uninstall_token("agent-1") and t1 != t2
    assert len(t1) == 23 and t1.count("-") == 3
    assert uninstall_token_sha256("agent-1") == hashlib.sha256(t1.encode()).hexdigest()


def _beats(*beats):
    """Feed (session, seq, t) heartbeats; returns each anomaly."""
    from app.services.agent_tamper import heartbeat_anomaly

    state, out = {}, []
    for session, seq, t in beats:
        state, anomaly = heartbeat_anomaly(state, session, seq, t)
        out.append(anomaly)
        state = {k: str(v) for k, v in state.items()}  # as Redis hands it back
    return out


def test_a_restart_is_a_new_session_not_an_anomaly():
    assert _beats(("A", 1, 0), ("A", 2, 30), ("B", 1, 60), ("B", 2, 90)) == [None] * 4
    assert _beats(("A", 1, 0), (None, None, 30)) == [None, None]  # agents before 1.8.0


def test_interleaving_sessions_are_a_copied_token():
    assert _beats(("A", 5, 0), ("B", 1, 10), ("A", 6, 30), ("B", 2, 40)) == [
        None, None, "duplicate_session", "duplicate_session"]
    # long after a restart, an old session coming back is not "interleaving"
    assert _beats(("A", 5, 0), ("B", 1, 10), ("A", 6, 10_000)) == [None, None, None]


def test_a_sequence_going_back_is_a_replay():
    assert _beats(("A", 1, 0), ("A", 2, 30), ("A", 2, 60), ("A", 3, 90)) == [None, None, "replay", None]
