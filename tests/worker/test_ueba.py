# tests/worker/test_ueba.py
import base64
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../worker'))

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from worker.ueba import explain as ex
from worker.ueba import model_codec as mc
from worker.ueba.features import IP_FEATURE_KEYS, USER_FEATURE_KEYS


def _fit(n_features=7, seed=0):
    X = np.random.default_rng(seed).normal(size=(300, n_features))
    return IsolationForest(n_estimators=50, contamination=0.05, random_state=42).fit(X)


# ─── model codec ─────────────────────────────────────────────────

def test_codec_round_trip_scores_identically():
    model = _fit()
    blob = mc.dumps_model(model, IP_FEATURE_KEYS, {"x": {"median": 1.0}}, 300, "t")
    bundle = mc.loads_model(blob)
    X = np.vstack([np.random.default_rng(1).normal(size=(200, 7)), np.full((5, 7), 8.0)])
    assert np.array_equal(model.decision_function(X), bundle.model.decision_function(X))
    assert np.array_equal(model.predict(X), bundle.model.predict(X))
    assert bundle.feature_keys == IP_FEATURE_KEYS and bundle.n_samples == 300
    assert bundle.baseline == {"x": {"median": 1.0}}


def test_codec_rejects_old_format_and_corrupt_blobs():
    v1 = base64.b64encode(json.dumps({"format": "isoforest-v1"}).encode()).decode()
    assert mc.loads_model(v1) is None
    payload = json.loads(__import__("zlib").decompress(base64.b64decode(mc.dumps_model(_fit(), IP_FEATURE_KEYS))))
    payload["estimators"][0]["nodes"]["left_child"] = [0]  # wrong length
    corrupt = base64.b64encode(__import__("zlib").compress(json.dumps(payload).encode())).decode()
    with pytest.raises(ValueError):
        mc.loads_model(corrupt)


def test_scorer_ignores_unusable_models_once(monkeypatch):
    from worker.ueba import scorer
    v1 = base64.b64encode(json.dumps({"format": "isoforest-v1"}).encode()).decode()
    assert scorer._decode("ip", v1) is None
    assert scorer._decode("ip", "not-base64!!") is None
    wrong_keys = mc.dumps_model(_fit(n_features=8), USER_FEATURE_KEYS)
    assert scorer._decode("ip", wrong_keys) is None  # trained for users
    assert scorer._decode("ip", mc.dumps_model(_fit(), IP_FEATURE_KEYS)) is not None


# ─── explanations ────────────────────────────────────────────────

def _ip_population():
    rng = np.random.default_rng(3)
    rows = [{
        "unique_users": float(rng.integers(1, 3)), "total_events": float(rng.integers(5, 40)),
        "failed_ratio": float(rng.uniform(0, 0.1)), "unique_target_hosts": 1.0,
        "hour_of_day": float(rng.integers(8, 18)), "is_weekend": 0.0, "failed_count": float(rng.integers(0, 3)),
    } for _ in range(200)]
    return ex.build_baseline(rows, IP_FEATURE_KEYS)


def test_brute_force_ip_is_explained_and_mapped_to_mitre():
    base = _ip_population()
    attack = {"unique_users": 40.0, "total_events": 900.0, "failed_ratio": 0.97,
              "unique_target_hosts": 1.0, "hour_of_day": 3.0, "is_weekend": 0.0, "failed_count": 870.0}
    reasons = ex.explain("ip", attack, None, base)
    features = [r["feature"] for r in reasons]
    assert len(reasons) <= ex.MAX_REASONS
    assert {"failed_count", "unique_users"} <= set(features) or {"failed_ratio", "unique_users"} <= set(features)
    assert any("all entities" in r["text"] for r in reasons)
    ids = [m["id"] for m in ex.mitre_for("ip", reasons)]
    assert "T1110" in ids and "T1110.003" in ids
    assert len(ids) == len(set(ids))


def test_normal_or_quieter_activity_has_no_reasons():
    base = _ip_population()
    normal = {"unique_users": 1.0, "total_events": 20.0, "failed_ratio": 0.05,
              "unique_target_hosts": 1.0, "hour_of_day": 10.0, "is_weekend": 0.0, "failed_count": 1.0}
    assert ex.explain("ip", normal, None, base) == []
    quiet = dict(normal, total_events=0.0, unique_users=0.0)
    assert ex.explain("ip", quiet, None, base) == []


def test_rare_hour_and_new_ip_for_a_user_use_its_own_baseline():
    own = ex.build_baseline([{
        "login_count": 10.0, "failed_ratio": 0.0, "unique_ips": 1.0, "unique_hosts": 1.0,
        "sudo_count": 0.0, "new_ip_seen": 0.0, "hour_of_day": float(9 + i % 8), "is_weekend": 0.0,
    } for i in range(48)], USER_FEATURE_KEYS)
    feat = {"login_count": 12.0, "failed_ratio": 0.0, "unique_ips": 1.0, "unique_hosts": 1.0,
            "sudo_count": 0.0, "new_ip_seen": 1.0, "hour_of_day": 2.0, "is_weekend": 0.0}
    reasons = ex.explain("user", feat, own, population={})
    texts = " | ".join(r["text"] for r in reasons)
    assert "never seen" in texts and "02:00 UTC" in texts and "its own baseline" in texts
    assert [m["id"] for m in ex.mitre_for("user", reasons)] == ["T1078"]


def test_failure_ratio_needs_volume():
    base = _ip_population()
    one_failure = {"unique_users": 1.0, "total_events": 1.0, "failed_ratio": 1.0,
                   "unique_target_hosts": 1.0, "hour_of_day": 10.0, "is_weekend": 0.0, "failed_count": 1.0}
    assert ex.explain("ip", one_failure, None, base) == []


def test_entity_profile_needs_enough_history():
    thin = ex.build_baseline([{"failed_ratio": 0.0}] * 3, ["failed_ratio"])
    pop = ex.build_baseline([{"failed_ratio": 0.5}] * 50, ["failed_ratio"])
    # 3 snapshots is too few: compare against the population instead
    assert ex.explain("user", {"failed_ratio": 0.6}, thin, pop) == []


# ─── anomaly decision ────────────────────────────────────────────

def test_assess_requires_an_explanation_and_survives_forest_saturation():
    strong = [{"feature": "failed_count", "z": 250.0, "value": 400, "text": ""}]
    mild = [{"feature": "unique_ips", "z": 3.2, "value": 4, "text": ""}]
    # forest outlier with nothing deviating: the model's contamination noise
    assert ex.assess(-0.2, 0.0, []) == 0.0
    # forest saturated (barely below its boundary) but a huge deviation: anomaly
    assert ex.assess(-0.026, 0.0, strong) == 1.0
    # forest says normal, deviation strong enough on its own
    assert ex.assess(0.05, 0.0, strong) == 1.0
    # forest says normal and only a mild deviation: not an anomaly
    assert ex.assess(0.05, 0.0, mild) == 0.0
    # forest outlier explained by a mild deviation: weak anomaly
    assert 0 < ex.assess(-0.03, 0.0, mild) < 0.5


# ─── risk ────────────────────────────────────────────────────────

def test_normal_scores_never_raise_risk():
    assert ex.anomaly_strength(0.2, -0.1) == 0.0
    assert ex.anomaly_strength(-0.05, -0.1) == 0.0
    assert ex.next_risk(30.0, 0, 0.0) == 30.0


def test_risk_decays_with_time_and_accumulates_with_anomalies():
    assert ex.next_risk(80.0, ex.RISK_HALF_LIFE, 0.0) == pytest.approx(40.0)
    assert ex.anomaly_strength(-0.5, -0.1) == 1.0
    r1 = ex.next_risk(0.0, 0, 1.0)
    r2 = ex.next_risk(r1, 60, 1.0)
    r3 = ex.next_risk(r2, 60, 1.0)
    assert 0 < r1 < r2 < r3 < 100
    assert r3 >= 80  # three strong anomalies in a row → critical
    assert ex.next_risk(0.0, 0, 0.01) < 20  # a marginal anomaly alone stays low
