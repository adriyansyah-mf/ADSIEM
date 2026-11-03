"""Train the static PE model on EMBER 2018 and export it for the agent.

    python ml/train.py <ember2018 dir> <out model.json.gz>

Labelled samples only (EMBER's -1 are unlabelled). Thresholds are chosen on
EMBER's test set at 1% and 0.1% false positives; both, with the detection
rate they give, go into the model file, which agent/internal/mlscore reads.
"""
from __future__ import annotations

import gzip
import json
import os
import sys
from multiprocessing import Pool

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from vectorize import DIM, vector  # noqa: E402


def _load(path: str) -> tuple[str, str, int]:
    """Vectorise one JSONL file into <path>.X.npy / .y.npy (kept between runs)."""
    xp, yp = path + ".X.npy", path + ".y.npy"
    if os.path.exists(xp) and os.path.exists(yp):
        return xp, yp, int(np.load(yp, mmap_mode="r").shape[0])
    xs, ys = [], []
    with open(path) as f:
        for line in f:
            raw = json.loads(line)
            if raw.get("label") not in (0, 1):
                continue
            xs.append(np.asarray(vector(raw), dtype=np.float32))
            ys.append(raw["label"])
    X = np.vstack(xs) if xs else np.zeros((0, DIM), np.float32)
    np.save(xp, X)
    np.save(yp, np.asarray(ys, np.int8))
    return xp, yp, X.shape[0]


def load(paths: list[str]) -> tuple[np.ndarray, np.ndarray]:
    """One preallocated array filled from the per-file .npy (no 2x peak)."""
    # each worker holds one file twice while stacking (~2 GB for EMBER's
    # larger files), so a few at a time
    with Pool(min(len(paths), int(os.environ.get("ML_LOAD_WORKERS", "3")))) as pool:
        parts = pool.map(_load, paths)
    n = sum(p[2] for p in parts)
    X, y, at = np.empty((n, DIM), np.float32), np.empty(n, np.int8), 0
    for xp, yp, k in parts:
        X[at:at + k] = np.load(xp, mmap_mode="r")
        y[at:at + k] = np.load(yp)
        at += k
    return X, y


def threshold_at(scores: np.ndarray, labels: np.ndarray, fpr: float) -> tuple[float, float]:
    benign = np.sort(scores[labels == 0])
    t = float(benign[int(len(benign) * (1 - fpr))])
    tpr = float((scores[labels == 1] > t).mean())
    return t, tpr


def flatten(tree: dict) -> dict:
    """LightGBM's nested tree as arrays: node i is internal when i < len(f);
    a child c >= 0 is a node, c < 0 is leaf ~c."""
    f, t, left, right, default_left, missing, leaves = [], [], [], [], [], [], []

    def walk(node) -> int:
        if "leaf_value" in node:
            leaves.append(float(node["leaf_value"]))
            return ~(len(leaves) - 1)
        i = len(f)
        f.append(int(node["split_feature"]))
        t.append(float(node["threshold"]))
        default_left.append(bool(node.get("default_left", True)))
        missing.append({"None": 0, "Zero": 1, "NaN": 2}.get(node.get("missing_type", "None"), 0))
        left.append(0)
        right.append(0)
        if node.get("decision_type", "<=") != "<=":
            raise ValueError("only numerical <= splits are exported")
        left[i] = walk(node["left_child"])
        right[i] = walk(node["right_child"])
        return i

    root = walk(tree["tree_structure"])
    return {"root": root, "f": f, "t": t, "l": left, "r": right, "dl": default_left, "m": missing, "v": leaves}


def main(data: str, out: str) -> None:
    train_files = sorted(os.path.join(data, n) for n in os.listdir(data) if n.startswith("train_features_"))
    X, y = load(train_files)
    print(f"train {X.shape} malicious {int(y.sum())}", flush=True)
    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 64, "max_depth": -1,
              "feature_fraction": 0.5, "bagging_fraction": 0.5, "bagging_freq": 1, "min_data_in_leaf": 50,
              "verbose": -1, "num_threads": os.cpu_count() or 4}
    ds = lgb.Dataset(X, y, free_raw_data=True).construct()
    train_samples = int(len(y))
    del X  # the binned dataset is much smaller
    model = lgb.train(params, ds, num_boost_round=500)
    Xt, yt = load([os.path.join(data, "test_features.jsonl")])
    print(f"test {Xt.shape}", flush=True)
    scores = model.predict(Xt)
    t1, tpr1 = threshold_at(scores, yt, 0.01)
    t01, tpr01 = threshold_at(scores, yt, 0.001)
    from sklearn_free_auc import auc  # local helper below
    metrics = {"auc": auc(scores, yt), "tpr_at_fpr_1pct": tpr1, "tpr_at_fpr_0_1pct": tpr01,
               "test_samples": int(len(yt)), "train_samples": train_samples}
    print(json.dumps(metrics), flush=True)
    dump = model.dump_model()
    payload = {
        "format": 1, "dim": DIM, "objective": "binary",
        "trees": [flatten(t) for t in dump["tree_info"]],
        "thresholds": {"fpr_1pct": t1, "fpr_0_1pct": t01},
        "metrics": metrics,
        "dataset": "EMBER 2018 v2 (Anderson & Roth 2018), labelled samples",
    }
    with gzip.open(out, "wt") as f:
        json.dump(payload, f, separators=(",", ":"))
    # a few vectors and scores for the Go evaluator's parity test
    sample = {"vectors": Xt[:50].tolist(), "scores": scores[:50].tolist()}
    with gzip.open(out.replace(".json.gz", ".parity.json.gz"), "wt") as f:
        json.dump(sample, f)
    print("wrote", out, flush=True)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
