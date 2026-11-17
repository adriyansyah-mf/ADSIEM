"""Score host names with the phishing domain model (ml/phish/train.py).

The model is LightGBM's dump_model() as gzip JSON; this walks its trees, so
the worker needs no LightGBM. Scores are cached per name: a DNS stream asks
about the same names over and over.
"""
from __future__ import annotations

import gzip
import json
import math
from functools import lru_cache
from pathlib import Path

from . import features as F

MODEL_PATH = Path(__file__).parent / "assets" / "model.json.gz"


def _walk(node: dict, x: list[float]) -> float:
    while "leaf_value" not in node:
        v = x[node["split_feature"]]
        dt = node.get("decision_type", "<=")
        if v != v:  # NaN: LightGBM's missing direction
            go_left = node.get("default_left", True)
        elif dt == "<=":
            go_left = v <= node["threshold"]
        else:  # "==" categorical: thresholds "a||b||c"
            go_left = str(int(v)) in str(node["threshold"]).split("||")
        node = node["left_child"] if go_left else node["right_child"]
    return node["leaf_value"]


class Model:
    def __init__(self, data: dict):
        if data.get("kind") != "phishing_domain":
            raise ValueError("not a phishing domain model")
        if data.get("feature_version") != F.FEATURE_VERSION or list(data.get("features", [])) != list(F.FEATURES):
            raise ValueError("model built from other features: retrain with ml/phish/train.py")
        self.trees = [t["tree_structure"] for t in data["trees"]]
        self.thresholds: dict[str, float] = data.get("thresholds", {})
        self.report: dict = data.get("report", {})

    @classmethod
    def load(cls, path: Path | str = MODEL_PATH) -> "Model":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return cls(json.load(f))

    def score_features(self, x: list[float]) -> float:
        raw = sum(_walk(t, x) for t in self.trees)
        return 1.0 / (1.0 + math.exp(-raw))

    def score(self, name: str) -> float | None:
        """Probability that name is a phishing host; None for names the
        model does not judge (addresses, reverse lookups, single labels)."""
        name = F.normalize(name)
        if not F.scorable(name):
            return None
        return _cached(self, name)


@lru_cache(maxsize=50_000)
def _cached(model: Model, name: str) -> float:
    return model.score_features(F.features(name))


@lru_cache(maxsize=1)
def default() -> Model | None:
    try:
        return Model.load()
    except (OSError, ValueError):
        return None
