"""Regression tests for the UEBA model codec.

sklearn >= 1.5 makes ``Tree`` attributes read-only, so the codec rebuilds trees
through ``Tree.__setstate__`` and recomputes the two caches sklearn fills during
``fit``. These tests assert the round-trip is numerically identical, which is
the only thing that proves the recomputed caches are right.
"""
import json
import base64

import numpy as np
import pytest

from worker.ueba.model_codec import _FORMAT, dumps_model, loads_model

sklearn = pytest.importorskip("sklearn")
from sklearn.ensemble import IsolationForest  # noqa: E402


def _fitted(n_estimators=6, n_samples=200, n_features=4, max_samples=64, seed=0):
    rng = np.random.RandomState(seed)
    X = rng.rand(n_samples, n_features)
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        random_state=seed,
    ).fit(X)
    return model, X


def test_roundtrip_decision_function_is_identical():
    model, X = _fitted()
    restored = loads_model(dumps_model(model))

    assert restored is not None
    expected = model.decision_function(X)
    actual = restored.decision_function(X)
    assert np.allclose(expected, actual)


def test_roundtrip_preserves_payload_shape():
    model, _ = _fitted(n_estimators=3)
    payload = json.loads(base64.b64decode(dumps_model(model)))

    assert payload["format"] == _FORMAT
    assert payload["n_estimators"] == 3
    assert len(payload["estimators"]) == 3
    assert payload["estimators"][0]["missing_go_to_left"] is not None


def test_restored_model_scores_unseen_points_like_original():
    model, X = _fitted(seed=7)
    restored = loads_model(dumps_model(model))

    novel = np.random.RandomState(99).rand(25, X.shape[1])
    assert np.allclose(model.decision_function(novel), restored.decision_function(novel))


def test_unknown_format_returns_none():
    blob = base64.b64encode(json.dumps({"format": "isoforest-v0"}).encode()).decode()
    assert loads_model(blob) is None


def test_trees_are_rebuilt_with_real_node_counts():
    model, _ = _fitted(n_estimators=2)
    restored = loads_model(dumps_model(model))

    for original, rebuilt in zip(model.estimators_, restored.estimators_):
        assert rebuilt.tree_.node_count == original.tree_.node_count
        assert np.array_equal(rebuilt.tree_.children_left, original.tree_.children_left)
        assert np.allclose(rebuilt.tree_.threshold, original.tree_.threshold)
