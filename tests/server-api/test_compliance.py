from types import SimpleNamespace

from app.services.compliance import _aggregate_hardening_category


def _snap(hardening_checks):
    return SimpleNamespace(hardening_checks=hardening_checks)


def test_no_checks_for_category_returns_none():
    snap = _snap([{"category": "ssh", "status": "pass", "title": "SSH check"}])
    assert _aggregate_hardening_category(snap, "kernel") is None


def test_empty_hardening_checks_returns_none():
    snap = _snap([])
    assert _aggregate_hardening_category(snap, "network") is None


def test_all_not_applicable_returns_not_automated():
    snap = _snap([
        {"category": "network", "status": "not_applicable", "title": "firewalld check"},
        {"category": "network", "status": "not_applicable", "title": "nftables check"},
    ])
    result = _aggregate_hardening_category(snap, "network")
    assert result["status"] == "not_automated"


def test_all_applicable_pass_returns_met():
    snap = _snap([
        {"category": "account", "status": "pass", "title": "No empty passwords"},
        {"category": "account", "status": "pass", "title": "PASS_MAX_DAYS set"},
    ])
    result = _aggregate_hardening_category(snap, "account")
    assert result["status"] == "met"


def test_mixed_pass_fail_returns_partial():
    snap = _snap([
        {"category": "ssh", "status": "pass", "title": "PermitRootLogin no"},
        {"category": "ssh", "status": "fail", "title": "PasswordAuthentication yes"},
    ])
    result = _aggregate_hardening_category(snap, "ssh")
    assert result["status"] == "partial"
    assert "PasswordAuthentication yes" in result["evidence"]


def test_all_applicable_fail_returns_gap():
    snap = _snap([
        {"category": "kernel", "status": "fail", "title": "ASLR disabled"},
        {"category": "kernel", "status": "fail", "title": "ptrace_scope permissive"},
    ])
    result = _aggregate_hardening_category(snap, "kernel")
    assert result["status"] == "gap"


def test_error_status_is_distinct_from_fail():
    snap = _snap([
        {"category": "account", "status": "pass", "title": "PASS_MAX_DAYS set"},
        {"category": "account", "status": "error", "title": "No local account has an empty password"},
    ])
    result = _aggregate_hardening_category(snap, "account")
    assert result["status"] == "partial"
    assert "could not be evaluated" in result["evidence"].lower()
    assert "No local account has an empty password" in result["evidence"]
    assert "failing" not in result["evidence"].lower()


def test_all_errors_no_failures_is_partial_not_gap():
    snap = _snap([
        {"category": "account", "status": "error", "title": "No local account has an empty password"},
    ])
    result = _aggregate_hardening_category(snap, "account")
    assert result["status"] == "partial"


def test_mixed_fail_and_error_distinguishes_both_in_evidence():
    snap = _snap([
        {"category": "ssh", "status": "fail", "title": "PasswordAuthentication yes"},
        {"category": "ssh", "status": "error", "title": "Could not read sshd_config"},
    ])
    result = _aggregate_hardening_category(snap, "ssh")
    assert result["status"] == "gap"
    assert "PasswordAuthentication yes" in result["evidence"]
    assert "Could not read sshd_config" in result["evidence"]
