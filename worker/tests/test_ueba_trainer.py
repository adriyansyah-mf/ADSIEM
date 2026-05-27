import statistics
import pytest

def _compute_profile(snapshots_features: list[dict], keys: list[str]) -> dict:
    """Pure function extracted from trainer logic for testability."""
    profile = {}
    for key in keys:
        values = [float(s.get(key, 0.0)) for s in snapshots_features]
        if len(values) >= 2:
            profile[key] = {"mean": statistics.mean(values), "std": statistics.stdev(values) or 0.1}
        else:
            profile[key] = {"mean": values[0] if values else 0.0, "std": 0.1}
    return profile

def test_profile_mean_std():
    snaps = [{"login_count": 2.0}, {"login_count": 4.0}, {"login_count": 6.0}]
    profile = _compute_profile(snaps, ["login_count"])
    assert profile["login_count"]["mean"] == pytest.approx(4.0)
    assert profile["login_count"]["std"]  == pytest.approx(2.0)

def test_profile_fills_missing_with_zero():
    snaps = [{"login_count": 5.0}]
    profile = _compute_profile(snaps, ["login_count", "sudo_count"])
    assert profile["sudo_count"]["mean"] == 0.0

def test_profile_std_floor():
    # Single snapshot or all-same values → std should be at least 0.1
    snaps = [{"login_count": 3.0}, {"login_count": 3.0}]
    profile = _compute_profile(snaps, ["login_count"])
    assert profile["login_count"]["std"] >= 0.1
