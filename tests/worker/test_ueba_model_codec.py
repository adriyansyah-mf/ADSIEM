"""Regression tests for the UEBA model codec.

sklearn >= 1.5 makes ``Tree`` attributes read-only, so the codec rebuilds trees
through ``Tree.__setstate__`` and restores the caches sklearn fills during
``fit``. These tests assert the round-trip is numerically identical, which is
the only thing that proves the restored model scores like the original.
"""
import base64
import json
import zlib

import numpy as np
import pytest

sklearn = pytest.importorskip("sklearn")
from sklearn.ensemble import IsolationForest  # noqa: E402

from worker.ueba.model_codec import _FORMAT, dumps_model, loads_model  # noqa: E402


def _fitted(n_estimators=6, n_samples=200, n_features=4, max_samples=64, seed=0):
    rng = np.random.RandomState(seed)
    X = rng.rand(n_samples, n_features)
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        random_state=seed,
    ).fit(X)
    return model, X


def _dump(model):
    return dumps_model(model, [f"f{i}" for i in range(model.n_features_in_)])


def _roundtrip(model):
    bundle = loads_model(_dump(model))
    assert bundle is not None
    return bundle.model


def test_roundtrip_decision_function_is_identical():
    model, X = _fitted()
    assert np.allclose(model.decision_function(X), _roundtrip(model).decision_function(X))


def test_roundtrip_preserves_payload_shape():
    model, _ = _fitted(n_estimators=3)
    payload = json.loads(zlib.decompress(base64.b64decode(_dump(model))))

    assert payload["format"] == _FORMAT
    assert len(payload["estimators"]) == 3
    assert payload["feature_keys"] == ["f0", "f1", "f2", "f3"]


def test_restored_model_scores_unseen_points_like_original():
    model, X = _fitted(seed=7)
    restored = _roundtrip(model)

    novel = np.random.RandomState(99).rand(25, X.shape[1])
    assert np.allclose(model.decision_function(novel), restored.decision_function(novel))


def test_unknown_format_returns_none():
    blob = base64.b64encode(json.dumps({"format": "isoforest-v0"}).encode()).decode()
    assert loads_model(blob) is None


def test_trees_are_rebuilt_with_real_node_counts():
    model, _ = _fitted(n_estimators=2)
    restored = _roundtrip(model)

    for original, rebuilt in zip(model.estimators_, restored.estimators_):
        assert rebuilt.tree_.node_count == original.tree_.node_count
        assert np.array_equal(rebuilt.tree_.children_left, original.tree_.children_left)
        assert np.allclose(rebuilt.tree_.threshold, original.tree_.threshold)
