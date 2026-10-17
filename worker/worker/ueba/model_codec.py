# worker/worker/ueba/model_codec.py
"""Safe IsolationForest serialization (no pickle on Redis data).

`pickle.loads` on a Redis-stored blob executes arbitrary code if Redis is ever
tampered with. sklearn models are ultimately plain numeric arrays, so we persist
those arrays as JSON and rebuild an equivalent estimator whose ``decision_function``
is sklearn's own implementation — loading is pure data, never code execution.
"""
import base64
import json

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeRegressor
from sklearn.tree._tree import Tree

_FORMAT = "isoforest-v1"


def dumps_model(model) -> str:
    payload = {
        "format": _FORMAT,
        "n_estimators": len(model.estimators_),
        "max_samples": int(model.max_samples_),
        "offset": float(model.offset_),
        "estimators": [],
    }
    for est in model.estimators_:
        t = est.tree_
        payload["estimators"].append({
            "n_features": int(t.n_features),
            "n_classes": int(t.n_classes) if hasattr(t, "n_classes") else 1,
            "children_left": t.children_left.tolist(),
            "children_right": t.children_right.tolist(),
            "feature": t.feature.tolist(),
            "threshold": t.threshold.tolist(),
            "impurity": t.impurity.tolist(),
            "n_node_samples": t.n_node_samples.tolist(),
            "weighted_n_node_samples": t.weighted_n_node_samples.tolist(),
            "value": t.value.reshape(-1).tolist(),
            "value_shape": list(t.value.shape),
        })
    return base64.b64encode(json.dumps(payload).encode()).decode()


def loads_model(blob_b64: str):
    raw = base64.b64decode(blob_b64)
    payload = json.loads(raw.decode())
    if payload.get("format") != _FORMAT:
        return None

    estimators = []
    for ed in payload["estimators"]:
        n_features = ed["n_features"]
        n_classes = ed["n_classes"]
        tree = Tree(n_features, np.array([n_classes], dtype=np.intp), 1)
        tree.children_left = np.asarray(ed["children_left"], dtype=np.int64)
        tree.children_right = np.asarray(ed["children_right"], dtype=np.int64)
        tree.feature = np.asarray(ed["feature"], dtype=np.int64)
        tree.threshold = np.asarray(ed["threshold"], dtype=np.float64)
        tree.impurity = np.asarray(ed["impurity"], dtype=np.float64)
        tree.n_node_samples = np.asarray(ed["n_node_samples"], dtype=np.int64)
        tree.weighted_n_node_samples = np.asarray(
            ed["weighted_n_node_samples"], dtype=np.float64
        )
        tree.value = np.asarray(ed["value"], dtype=np.float64).reshape(ed["value_shape"])

        reg = DecisionTreeRegressor()
        reg.tree_ = tree
        reg.n_features_in_ = n_features
        estimators.append(reg)

    model = IsolationForest()
    model.estimators_ = estimators
    model.max_samples_ = payload["max_samples"]
    model.offset_ = payload["offset"]
    model.n_features_in_ = estimators[0].n_features_in_
    return model
