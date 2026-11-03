"""Train the static models on EMBER2024 (feature version 3) and export them.

    python ml/v3/train.py <ember2024 dir> <out model.json.gz> [--kind pe|elf] [--cache DIR]

PE: Win32, Win64 and .NET training files (sampled per source to fit in
memory), thresholds and metrics on their test files. ELF: ELF_train /
ELF_test. Samples are chosen by their SHA-256 (deterministic). Vectors come
from ml/v3/vectorize.py, which the agent reproduces in Go
(agent/internal/mlscore/vector_v3.go). The model file is read by
agent/internal/mlscore (format 2, features v3).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sys
import zipfile
from multiprocessing import Pool

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from vectorize import DIM, GROUPS, vector  # noqa: E402  (ml/v3/vectorize.py)

assert DIM == sum(n for _, n in GROUPS) == 2472, "not the v3 vectoriser"

# source zip[week slice] -> records to keep (about); the totals are EMBER2024's.
# Win32_train (12 GB) may be missing: then the first 6 weeks of Win32_test
# train and every type is tested on the last 6 weeks (3 Nov - 14 Dec 2024).
PE_TRAIN = {"Win32_train.zip": 400_000, "Win64_train.zip": 400_000, "Dot_Net_train.zip": 300_000}
PE_TRAIN_NO_WIN32 = {"Win64_train.zip": 400_000, "Dot_Net_train.zip": 300_000, "Win32_test.zip[:6]": 240_000}
PE_TEST = {"Win32_test.zip[6:]": 60_000, "Win64_test.zip[6:]": 60_000, "Dot_Net_test.zip[6:]": 60_000}
ELF_TRAIN = {"ELF_train.zip": 60_000}
ELF_TEST = {"ELF_test.zip": 20_000}
TOTALS = {"Win32_train.zip": 2_080_000, "Win64_train.zip": 1_040_000, "Dot_Net_train.zip": 520_000,
          "ELF_train.zip": 52_000, "Win32_test.zip": 480_000, "Win64_test.zip": 240_000,
          "Dot_Net_test.zip": 120_000, "ELF_test.zip": 12_000}


def keep(sha: str, fraction: float) -> bool:
    if fraction >= 1:
        return True
    return int(hashlib.sha256(sha.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF < fraction


def _member(task):
    """Vectorise the kept records of one JSONL member of a zip into .npy."""
    zpath, name, fraction, cache = task
    base = os.path.join(cache, os.path.basename(zpath) + "__" + name.replace("/", "_"))
    xp, yp = base + ".X.npy", base + ".y.npy"
    if os.path.exists(xp) and os.path.exists(yp):
        return xp, yp, int(np.load(yp, mmap_mode="r").shape[0])
    xs, ys = [], []
    with zipfile.ZipFile(zpath) as z, z.open(name) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("label") not in (0, 1) or not keep(rec.get("sha256", ""), fraction):
                continue
            xs.append(np.asarray(vector(rec), dtype=np.float32))
            ys.append(rec["label"])
    X = np.vstack(xs) if xs else np.zeros((0, DIM), np.float32)
    np.save(xp, X)
    np.save(yp, np.asarray(ys, np.int8))
    return xp, yp, X.shape[0]


def _slice(spec: str):
    """"Win32_test.zip[:6]" -> ("Win32_test.zip", slice(None, 6))."""
    if "[" not in spec:
        return spec, slice(None)
    name, rest = spec.split("[", 1)
    a, b = rest.rstrip("]").split(":")
    return name, slice(int(a) if a else None, int(b) if b else None)


def load(data: str, sources: dict[str, int], cache: str, workers: int):
    tasks, kinds = [], []
    for spec, cap in sources.items():
        zname, sl = _slice(spec)
        zpath = os.path.join(data, zname)
        if not os.path.exists(zpath) or not os.path.exists(os.path.join(data, zname.replace(".zip", ".done"))):
            print(f"missing {zname}: left out", flush=True)
            continue
        with zipfile.ZipFile(zpath) as z:
            members = sorted(i.filename for i in z.infolist() if not i.is_dir())
        chosen = members[sl]
        fraction = min(1.0, cap / (TOTALS.get(zname, cap) * len(chosen) / len(members)))
        for name in chosen:
            tasks.append((zpath, name, fraction, cache))
            kinds.append("DotNet" if zname.startswith("Dot_Net") else zname.split("_")[0])
    with Pool(workers) as pool:
        parts = pool.map(_member, tasks)
    n = sum(p[2] for p in parts)
    X, y, kind = np.empty((n, DIM), np.float32), np.empty(n, np.int8), np.empty(n, dtype=object)
    at = 0
    for (xp, yp, k), kd in zip(parts, kinds):
        X[at:at + k] = np.load(xp, mmap_mode="r")
        y[at:at + k] = np.load(yp)
        kind[at:at + k] = kd
        at += k
    return X, y, kind


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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--kind", choices=("pe", "elf"), default="pe")
    ap.add_argument("--cache", default="")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rounds", type=int, default=800)
    ap.add_argument("--leaves", type=int, default=128)
    args = ap.parse_args()
    cache = args.cache or os.path.join(args.data, "cache_v3")
    os.makedirs(cache, exist_ok=True)
    if args.kind == "pe":
        have32 = os.path.exists(os.path.join(args.data, "Win32_train.done"))
        train_src, test_src = (PE_TRAIN if have32 else PE_TRAIN_NO_WIN32), PE_TEST
        print("training on", list(train_src), flush=True)
    else:
        train_src, test_src = ELF_TRAIN, ELF_TEST

    X, y, _ = load(args.data, train_src, cache, args.workers)
    print(f"train {X.shape} malicious {int(y.sum())}", flush=True)
    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": args.leaves, "max_depth": -1,
              "feature_fraction": 0.5, "bagging_fraction": 0.5, "bagging_freq": 1, "min_data_in_leaf": 50,
              "verbose": -1, "num_threads": os.cpu_count() or 4}
    ds = lgb.Dataset(X, y, free_raw_data=True).construct()
    n_train = int(len(y))
    del X
    model = lgb.train(params, ds, num_boost_round=args.rounds)
    del ds

    Xt, yt, kt = load(args.data, test_src, cache, args.workers)
    print(f"test {Xt.shape}", flush=True)
    scores = model.predict(Xt)
    t1, tpr1 = threshold_at(scores, yt, 0.01)
    t01, tpr01 = threshold_at(scores, yt, 0.001)
    metrics = {"auc": auc(scores, yt), "tpr_at_fpr_1pct": tpr1, "tpr_at_fpr_0_1pct": tpr01,
               "test_samples": int(len(yt)), "train_samples": n_train, "by_type": {}}
    for kd in sorted(set(kt)):
        m = kt == kd
        s, l = scores[m], yt[m]
        metrics["by_type"][kd] = {
            "samples": int(m.sum()), "auc": auc(s, l),
            "tpr_at_threshold_1pct": float((s[l == 1] > t1).mean()), "fpr_at_threshold_1pct": float((s[l == 0] > t1).mean()),
            "tpr_at_threshold_0_1pct": float((s[l == 1] > t01).mean()),
            "fpr_at_threshold_0_1pct": float((s[l == 0] > t01).mean())}
    print(json.dumps(metrics, indent=1), flush=True)
    dump = model.dump_model()
    payload = {"format": 2, "features": "v3", "kind": args.kind, "dim": DIM,
               "trees": [flatten(t) for t in dump["tree_info"]],
               "thresholds": {"fpr_1pct": t1, "fpr_0_1pct": t01}, "metrics": metrics,
               "dataset": "EMBER2024 (Joyce et al. 2025), feature version 3 without authenticode/pefilewarnings"}
    with gzip.open(args.out, "wt") as f:
        json.dump(payload, f, separators=(",", ":"))
    pick = np.linspace(0, len(yt) - 1, 50).astype(int)
    with gzip.open(args.out.replace(".json.gz", ".parity.json.gz"), "wt") as f:
        json.dump({"vectors": Xt[pick].tolist(), "scores": scores[pick].tolist()}, f)
    print("wrote", args.out, flush=True)


if __name__ == "__main__":
    main()
