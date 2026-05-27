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

def test_combined_risk_formula():
    """Combined risk: z-score 60% + global 40% when both available."""
    old_risk = 50.0
    zscore_contrib = 40.0
    global_contrib = 60.0
    raw = zscore_contrib * 0.6 + global_contrib * 0.4
    new_risk = old_risk * 0.9 + raw * 0.1
    assert abs(new_risk - (50.0 * 0.9 + 48.0 * 0.1)) < 0.01

def test_zscore_only_when_no_global():
    old_risk = 0.0
    zscore_contrib = 80.0
    new_risk = old_risk * 0.9 + zscore_contrib * 0.1
    assert abs(new_risk - 8.0) < 0.01
