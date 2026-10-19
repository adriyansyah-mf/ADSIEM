# worker/worker/ueba/model_codec.py
"""Safe IsolationForest serialization (no pickle on Redis data).

`pickle.loads` on a Redis-stored blob executes arbitrary code if Redis is ever
tampered with. sklearn models are ultimately plain numeric arrays, so we persist
those arrays as JSON and rebuild an equivalent estimator whose
``decision_function`` is sklearn's own implementation — loading is pure data,
never code execution.

sklearn >= 1.5 made every ``Tree`` attribute read-only, so the tree is rebuilt
through ``Tree.__getstate__``/``__setstate__`` (the same dict pickle would carry)
and the two derived caches sklearn computes during ``fit``
(``_decision_path_lengths`` and ``_average_path_length_per_tree``) are
recomputed from the restored trees. Both formulas are verified against a fitted
model in ``worker/tests/test_ueba_model_codec.py``.
"""
import base64
import json

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.ensemble._iforest import _average_path_length
from sklearn.tree import DecisionTreeRegressor
from sklearn.tree._tree import Tree

_FORMAT = "isoforest-v2"

_FIELD_MAP = {
    "left_child": "children_left",
    "right_child": "children_right",
    "feature": "feature",
    "threshold": "threshold",
    "impurity": "impurity",
    "n_node_samples": "n_node_samples",
    "weighted_n_node_samples": "weighted_n_node_samples",
    "missing_go_to_left": "missing_go_to_left",
}


def dumps_model(model) -> str:
    payload = {
        "format": _FORMAT,
        "n_estimators": len(model.estimators_),
        "max_samples": int(model.max_samples_),
        "max_samples_value": int(model._max_samples),
        "max_features": int(model._max_features),
        "offset": float(model.offset_),
        "n_features_in": int(model.n_features_in_),
        "estimators_features": [list(map(int, f)) for f in model.estimators_features_],
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
            "missing_go_to_left": t.missing_go_to_left.tolist(),
            "value": np.asarray(t.value).reshape(-1).tolist(),
            "value_shape": list(t.value.shape),
        })
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _build_tree(ed: dict) -> Tree:
    n_features = ed["n_features"]
    n_classes = ed["n_classes"]
    n_nodes = len(ed["children_left"])

    tree = Tree(n_features, np.array([n_classes], dtype=np.intp), 1)
    state = tree.__getstate__()

    nodes = np.zeros(n_nodes, dtype=state["nodes"].dtype)
    for node_field, tree_attr in _FIELD_MAP.items():
        nodes[node_field] = np.asarray(ed[tree_attr])

    state["node_count"] = n_nodes
    state["nodes"] = nodes
    state["values"] = np.asarray(ed["value"], dtype=np.float64).reshape(n_nodes, 1, 1)
    tree.__setstate__(state)
    return tree


def _decision_path_lengths(tree: Tree) -> np.ndarray:
    depths = np.zeros(tree.node_count, dtype=np.int64)
    stack = [(0, 1)]
    while stack:
        node, depth = stack.pop()
        depths[node] = depth
        left = tree.children_left[node]
        right = tree.children_right[node]
        if left != -1:
            stack.append((left, depth + 1))
        if right != -1:
            stack.append((right, depth + 1))
    return depths


def loads_model(blob_b64: str):
    raw = base64.b64decode(blob_b64)
    payload = json.loads(raw.decode())
    if payload.get("format") != _FORMAT:
        return None

    estimators = []
    path_lengths = []
    avg_lengths = []

    for ed in payload["estimators"]:
        tree = _build_tree(ed)

        reg = DecisionTreeRegressor()
        reg.tree_ = tree
        reg.n_features_in_ = ed["n_features"]
        estimators.append(reg)

        path_lengths.append(_decision_path_lengths(tree))
        avg_lengths.append(_average_path_length(tree.n_node_samples))

    model = IsolationForest()
    model.estimators_ = estimators
    model.max_samples_ = payload["max_samples"]
    model.offset_ = payload["offset"]
    model.n_features_in_ = payload["n_features_in"]
    model._max_samples = payload["max_samples_value"]
    model._max_features = payload["max_features"]
    model.estimators_features_ = [np.asarray(f, dtype=np.intp)
                                  for f in payload["estimators_features"]]
    model._decision_path_lengths = tuple(path_lengths)
    model._average_path_length_per_tree = tuple(avg_lengths)
    return model
