import pytest
from worker.ueba.mitre_mapper import map_to_mitre

def test_brute_force_detected():
    feat = {"failed_ratio": 0.6, "login_count": 10.0}
    result = map_to_mitre(feat, "user")
    ids = [t["id"] for t in result]
    assert "T1110" in ids

def test_password_spray_detected_on_ip():
    feat = {"unique_users": 6.0, "failed_ratio": 0.3}
    result = map_to_mitre(feat, "ip")
    ids = [t["id"] for t in result]
    assert "T1110.003" in ids

def test_valid_accounts_new_ip():
    feat = {"new_ip_seen": 1.0, "unique_ips": 4.0}
    result = map_to_mitre(feat, "user")
    ids = [t["id"] for t in result]
    assert "T1078" in ids

def test_privilege_escalation():
    feat = {"sudo_count": 5.0}
    result = map_to_mitre(feat, "user")
    ids = [t["id"] for t in result]
    assert "T1548" in ids

def test_lateral_movement_host():
    feat = {"unique_source_ips": 6.0}
    result = map_to_mitre(feat, "host")
    ids = [t["id"] for t in result]
    assert "T1021" in ids

def test_no_false_matches_for_clean_user():
    feat = {"failed_ratio": 0.0, "login_count": 1.0, "sudo_count": 0.0,
            "new_ip_seen": 0.0, "unique_ips": 1.0}
    result = map_to_mitre(feat, "user")
    assert result == []

def test_result_structure():
    feat = {"failed_ratio": 0.6, "login_count": 8.0}
    result = map_to_mitre(feat, "user")
    assert all("id" in t and "name" in t for t in result)
