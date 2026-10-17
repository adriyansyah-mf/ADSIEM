# worker/worker/ueba/model_codec.py
"""Safe IsolationForest serialization (no pickle on Redis data).

`pickle.loads` on a Redis-stored blob executes arbitrary code if Redis is ever
tampered with. A fitted IsolationForest is plain numeric arrays, so we persist
those as JSON and rebuild the estimator; loading is pure data, and scoring is
sklearn's own ``decision_function``.

Trees are restored through ``Tree.__setstate__`` — the same path sklearn's own
unpickling uses — because a Tree's array attributes are read-only. Besides the
trees, IsolationForest scoring needs ``estimators_features_``,
``_decision_path_lengths`` and ``_average_path_length_per_tree``; all of them
are stored. The bundle also carries the feature order and a per-feature
baseline so anomalies can be explained.
"""
import base64
import json
import zlib
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeRegressor
from sklearn.tree._tree import Tree

_FORMAT = "isoforest-v2"


def _node_dtype() -> np.dtype:
    # The structured dtype of Tree.nodes for the installed sklearn version.
    return Tree(1, np.array([1], dtype=np.intp), 1).__getstate__()["nodes"].dtype


_NODE_DTYPE = _node_dtype()


@dataclass
class ModelBundle:
    model: IsolationForest
    feature_keys: list[str]
    baseline: dict[str, dict[str, float]] = field(default_factory=dict)
    n_samples: int = 0
    trained_at: str = ""


def _encode_tree(tree: Tree) -> dict:
    state = tree.__getstate__()
    nodes = state["nodes"]
    return {
        "n_features": int(tree.n_features),
        "max_depth": int(state["max_depth"]),
        "node_count": int(state["node_count"]),
        "nodes": {name: nodes[name].tolist() for name in nodes.dtype.names},
        "values": state["values"].reshape(-1).tolist(),
        "values_shape": list(state["values"].shape),
    }


def _decode_tree(ed: dict) -> Tree:
    node_count = int(ed["node_count"])
    nodes = np.zeros(node_count, dtype=_NODE_DTYPE)
    stored = ed["nodes"]
    for name in _NODE_DTYPE.names:
        if name not in stored:
            # e.g. a field added by a newer sklearn; only tolerate ones that
            # don't affect prediction (missing_go_to_left defaults to 0)
            if name != "missing_go_to_left":
                raise ValueError(f"tree is missing node field {name!r}")
            continue
        column = np.asarray(stored[name], dtype=_NODE_DTYPE[name])
        if column.shape != (node_count,):
            raise ValueError(f"node field {name!r} has the wrong length")
        nodes[name] = column
    values = np.asarray(ed["values"], dtype=np.float64).reshape(ed["values_shape"])
    tree = Tree(int(ed["n_features"]), np.array([1], dtype=np.intp), 1)
    tree.__setstate__({
        "max_depth": int(ed["max_depth"]),
        "node_count": node_count,
        "nodes": nodes,
        "values": values,
    })
    return tree


def dumps_model(model: IsolationForest, feature_keys: list[str],
                baseline: dict | None = None, n_samples: int = 0, trained_at: str = "") -> str:
    payload = {
        "format": _FORMAT,
        "feature_keys": list(feature_keys),
        "baseline": baseline or {},
        "n_samples": int(n_samples),
        "trained_at": trained_at,
        "n_features_in": int(model.n_features_in_),
        "max_samples": int(model._max_samples),
        "max_features": int(model._max_features),
        "offset": float(model.offset_),
        "estimators": [_encode_tree(est.tree_) for est in model.estimators_],
        "estimators_features": [np.asarray(f).tolist() for f in model.estimators_features_],
        "decision_path_lengths": [np.asarray(a).tolist() for a in model._decision_path_lengths],
        "average_path_length_per_tree": [np.asarray(a).tolist() for a in model._average_path_length_per_tree],
    }
    return base64.b64encode(zlib.compress(json.dumps(payload).encode(), 6)).decode()


def loads_model(blob_b64: str) -> ModelBundle | None:
    """Rebuild a fitted model. Returns None for blobs in an older format (they
    are replaced on the next training run); raises ValueError on corrupt data."""
    raw = base64.b64decode(blob_b64)
    try:
        raw = zlib.decompress(raw)
    except zlib.error:
        pass  # v1 blobs were uncompressed JSON; the format check below rejects them
    payload = json.loads(raw.decode())
    if payload.get("format") != _FORMAT:
        return None

    n_features = int(payload["n_features_in"])
    estimators = []
    for ed in payload["estimators"]:
        reg = DecisionTreeRegressor()
        reg.tree_ = _decode_tree(ed)
        reg.n_features_in_ = int(ed["n_features"])
        reg.n_outputs_ = 1
        reg.max_features_ = reg.n_features_in_
        estimators.append(reg)

    model = IsolationForest()
    model.estimators_ = estimators
    model.estimators_features_ = [np.asarray(f, dtype=np.intp) for f in payload["estimators_features"]]
    model._decision_path_lengths = [np.asarray(a, dtype=np.float64) for a in payload["decision_path_lengths"]]
    model._average_path_length_per_tree = [
        np.asarray(a, dtype=np.float64) for a in payload["average_path_length_per_tree"]
    ]
    model._max_samples = int(payload["max_samples"])
    model.max_samples_ = model._max_samples
    model._max_features = int(payload["max_features"])
    model.offset_ = float(payload["offset"])
    model.n_features_in_ = n_features
    if len({len(model.estimators_), len(model.estimators_features_),
            len(model._decision_path_lengths), len(model._average_path_length_per_tree)}) != 1:
        raise ValueError("inconsistent estimator arrays")

    return ModelBundle(
        model=model,
        feature_keys=list(payload["feature_keys"]),
        baseline=payload.get("baseline") or {},
        n_samples=int(payload.get("n_samples", 0)),
        trained_at=payload.get("trained_at", ""),
    )
