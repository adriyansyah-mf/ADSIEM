import pytest
from worker.ueba.features import (
    USER_FEATURE_KEYS, IP_FEATURE_KEYS, HOST_FEATURE_KEYS, vector_from_dict
)

def test_user_feature_keys_include_new():
    assert "velocity" in USER_FEATURE_KEYS
    assert "hour_deviation" in USER_FEATURE_KEYS

def test_ip_feature_keys_include_ti():
    assert "ti_reputation" in IP_FEATURE_KEYS

def test_host_feature_keys_complete():
    assert HOST_FEATURE_KEYS == [
        "unique_users", "total_events", "failed_ratio",
        "unique_source_ips", "sudo_count",
        "hour_of_day", "is_weekend", "velocity", "ti_reputation",
    ]

def test_vector_from_dict_fills_missing_with_zero():
    d = {"login_count": 3.0, "failed_ratio": 0.1}
    vec = vector_from_dict(d, ["login_count", "failed_ratio", "sudo_count"])
    assert vec == [3.0, 0.1, 0.0]
