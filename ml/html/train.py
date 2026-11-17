"""Train the agent's HTML page model (agent/internal/mlscore html.go).

Vectors come from the agent's own extractor (agent/cmd/htmlfeat), so
training and the agent never disagree on a feature:

  go run ./cmd/htmlfeat -malshare <dir> -warc a.warc.gz,b.warc.gz -out vectors.jsonl
  python ml/html/train.py --vectors vectors.jsonl --out agent/internal/mlscore/model_html.json.gz

Malicious: MalShare HTML samples (phishing kits, redirectors, HTML smuggling).
Benign: HTML responses from Common Crawl WARC files. The split is by group
(the host for crawled pages, the tag skeleton for samples), so no site and
no kit template is in both train and test. Thresholds give 1% and 0.1% false
positives on the held-out benign pages, like the PE model.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sys

import lightgbm as lgb
import numpy as np


# the same three helpers as ml/v3/train.py (the agent reads this tree format)
def threshold_at(scores, labels, fpr):
    benign = np.sort(scores[labels == 0])
    t = float(benign[min(int(len(benign) * (1 - fpr)), len(benign) - 1)])
    return t, float((scores[labels == 1] > t).mean())


def auc(scores, labels):
    order = np.argsort(scores)
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels == 1
    n_pos, n_neg = pos.sum(), (~pos).sum()
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def flatten(tree: dict) -> dict:
    f, t, left, right, dl, miss, leaves = [], [], [], [], [], [], []

    def walk(node) -> int:
        if "leaf_value" in node:
            leaves.append(float(node["leaf_value"]))
            return ~(len(leaves) - 1)
        i = len(f)
        f.append(int(node["split_feature"]))
        t.append(float(node["threshold"]))
        dl.append(bool(node.get("default_left", True)))
        miss.append({"None": 0, "Zero": 1, "NaN": 2}.get(node.get("missing_type", "None"), 0))
        left.append(0)
        right.append(0)
        if node.get("decision_type", "<=") != "<=":
            raise ValueError("only numerical <= splits are exported")
        left[i] = walk(node["left_child"])
        right[i] = walk(node["right_child"])
        return i

    root = walk(tree["tree_structure"])
    return {"root": root, "f": f, "t": t, "l": left, "r": right, "dl": dl, "m": miss, "v": leaves}


def fold(group: str, k: int = 5) -> int:
    return int(hashlib.sha256(group.encode()).hexdigest()[:8], 16) % k


def kinds(x: np.ndarray, names: list[str]) -> dict[str, np.ndarray]:
    f = {n: x[:, i] for i, n in enumerate(names)}
    return {
        "password_form": f["password_inputs"] > 0,
        "redirect": (f["meta_refresh"] > 0) | (f["location_assign"] > 0) | (f["settimeout_redirect"] > 0),
        "smuggling": (f["blob_api"] > 0) & ((f["download_attr"] > 0) | (f["msave_blob"] > 0)),
        "obfuscated": (f["eval"] > 0) | (f["atob"] > 0) | (f["unescape"] > 0) | (f["longest_b64"] > 1000),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--names", required=True, help="feature names, one per line (go test prints them)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", default="")
    a = ap.parse_args()

    names = [l.strip() for l in open(a.names) if l.strip()]
    X, y, groups, srcs = [], [], [], []
    for line in open(a.vectors):
        r = json.loads(line)
        X.append(r["x"])
        y.append(r["label"])
        groups.append(r["group"])
        srcs.append(r["src"])
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int8)
    assert X.shape[1] == len(names), (X.shape, len(names))
    folds = np.array([fold(g) for g in groups])
    test = folds == 0
    print(f"pages={len(y)} malicious={int(y.sum())} benign={int((y == 0).sum())} "
          f"test_mal={int(y[test].sum())} test_ben={int((y[test] == 0).sum())} "
          f"mal_groups={len({g for g, l in zip(groups, y) if l})}", flush=True)

    pos = y[~test].sum()
    params = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=20,
                  feature_fraction=0.8, bagging_fraction=0.9, bagging_freq=1, verbose=-1, seed=11,
                  scale_pos_weight=float(((y[~test] == 0).sum()) / max(pos, 1)) ** 0.5)
    dtr = lgb.Dataset(X[~test], y[~test], feature_name=names)
    dte = lgb.Dataset(X[test], y[test], reference=dtr)
    model = lgb.train(params, dtr, num_boost_round=800, valid_sets=[dte],
                      callbacks=[lgb.early_stopping(60, verbose=False)])
    s = model.predict(X[test], num_iteration=model.best_iteration)
    yt = y[test]
    t1, tpr1 = threshold_at(s, yt, 0.01)
    t01, tpr01 = threshold_at(s, yt, 0.001)
    metrics = {"auc": round(auc(s, yt), 5), "tpr_at_fpr_1pct": round(tpr1, 4), "tpr_at_fpr_0_1pct": round(tpr01, 4),
               "test_malicious": int(yt.sum()), "test_benign": int((yt == 0).sum()),
               "best_iteration": model.best_iteration}
    mal = X[test][yt == 1]
    sm = s[yt == 1]
    metrics["by_kind"] = {k: {"pages": int(m.sum()),
                              "at_1pct": round(float((sm[m] > t1).mean()), 3) if m.sum() else None,
                              "at_0_1pct": round(float((sm[m] > t01).mean()), 3) if m.sum() else None}
                          for k, m in kinds(mal, names).items()}
    imp = sorted(zip(names, model.feature_importance("gain")), key=lambda p: -p[1])
    metrics["top_features"] = [n for n, _ in imp[:12]]
    print(json.dumps(metrics, indent=1), flush=True)

    full = lgb.train(params, lgb.Dataset(X, y, feature_name=names),
                     num_boost_round=model.best_iteration or 300)
    dump = full.dump_model()
    payload = {"format": 2, "features": "html1", "kind": "html", "dim": len(names),
               "trees": [flatten(t) for t in dump["tree_info"]],
               "thresholds": {"fpr_1pct": t1, "fpr_0_1pct": t01}, "metrics": metrics,
               "dataset": "MalShare HTML samples (Dec 2025-Jan 2026) vs Common Crawl CC-MAIN-2026-39 HTML pages"}
    with gzip.open(a.out, "wt") as f:
        json.dump(payload, f, separators=(",", ":"))
    pick = np.linspace(0, len(y) - 1, 60).astype(int)
    with gzip.open(a.out.replace(".json.gz", ".parity.json.gz"), "wt") as f:
        json.dump({"vectors": X[pick].tolist(), "scores": full.predict(X[pick]).tolist()}, f)
    if a.report:
        json.dump(metrics, open(a.report, "w"), indent=1)
    print("wrote", a.out, flush=True)


if __name__ == "__main__":
    main()
