"""Train the phishing domain model (worker/worker/phishing).

Data (public, no key; see docs/operations/phishing-model.md):
  --phish   phishing host names, one per line (Phishing.Database
            phishing-domains-ACTIVE.txt) and/or URLs (OpenPhish feed.txt)
  --umbrella Cisco Umbrella top-1m.csv: real, mostly benign, DNS names with
            their subdomains (what a DNS sensor sees)
  --tranco  Tranco top-1m.csv: popular registered domains

Clean-up: a name on both sides is dropped; a phishing name under one of
Tranco's top 1000 registered domains is dropped (a page on a big platform
cannot be judged from its host name). The split is by registered domain, so
no domain is in both train and test. The model is LightGBM, exported like the
PE model: dump_model() as gzip JSON, plus the score thresholds that give
1e-3, 1e-4 and 1e-5 false positives on the held-out benign names.

  python ml/phish/train.py --phish a.txt --phish feed.txt --umbrella top-1m.csv \
      --tranco tranco.csv --out worker/worker/phishing/assets/model.json.gz
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import sys
from multiprocessing import Pool
from urllib.parse import urlsplit

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))
from worker.phishing import features as F  # noqa: E402

FPRS = (1e-3, 1e-4, 1e-5)


def read_phish(paths: list[str]) -> set[str]:
    out = set()
    for p in paths:
        for line in open(p, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = urlsplit(line).hostname if "://" in line else line.split("/")[0]
            host = F.normalize(host or "")
            if F.scorable(host):
                out.add(host)
    return out


def read_ranked(path: str, limit: int | None = None) -> list[str]:
    out = []
    for line in open(path, encoding="utf-8", errors="ignore"):
        parts = line.strip().split(",")
        if len(parts) < 2:
            continue
        host = F.normalize(parts[1])
        if F.scorable(host):
            out.append(host)
        if limit and len(out) >= limit:
            break
    return out


def _feat(name: str) -> list[float]:
    return F.features(name)


def _fold(regdom: str) -> int:
    return int(hashlib.sha256(regdom.encode()).hexdigest()[:8], 16) % 5


def threshold_at(benign_scores: np.ndarray, fpr: float) -> float:
    """The lowest score whose false positive rate on benign_scores is at most fpr."""
    s = np.sort(benign_scores)[::-1]
    k = int(np.floor(fpr * len(s)))
    return float(s[k]) + 1e-9 if k < len(s) else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", action="append", required=True)
    ap.add_argument("--umbrella", required=True)
    ap.add_argument("--tranco", required=True)
    ap.add_argument("--tranco-benign", type=int, default=300_000)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", default="")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    a = ap.parse_args()

    psl = F.default_psl()
    phish = read_phish(a.phish)
    umbrella = read_ranked(a.umbrella)
    tranco = read_ranked(a.tranco)
    top1k = {F.registered_domain(d, psl) for d in tranco[:1000]}
    benign = set(umbrella) | set(tranco[: a.tranco_benign])
    both = phish & benign
    phish -= both
    benign -= both
    dropped_top = {p for p in phish if F.registered_domain(p, psl) in top1k}
    phish -= dropped_top
    print(f"phish={len(phish)} benign={len(benign)} dropped_both={len(both)} dropped_top1k={len(dropped_top)}",
          flush=True)

    names = sorted(phish) + sorted(benign)
    y = np.array([1] * len(phish) + [0] * len(benign), dtype=np.int8)
    folds = np.array([_fold(F.registered_domain(n, psl)) for n in names])
    with Pool(a.jobs) as pool:
        X = np.array(pool.map(_feat, names, chunksize=2000), dtype=np.float32)
    print(f"features: {X.shape}", flush=True)

    test = folds == 0
    params = dict(objective="binary", learning_rate=0.05, num_leaves=63, min_data_in_leaf=50,
                  feature_fraction=0.9, bagging_fraction=0.9, bagging_freq=1, verbose=-1, seed=7)
    dtrain = lgb.Dataset(X[~test], y[~test], feature_name=list(F.FEATURES), free_raw_data=False)
    dvalid = lgb.Dataset(X[test], y[test], reference=dtrain)
    model = lgb.train(params, dtrain, num_boost_round=600, valid_sets=[dvalid],
                      callbacks=[lgb.early_stopping(50, verbose=False)])
    p = model.predict(X[test], num_iteration=model.best_iteration)
    yt = y[test]
    ben, mal = p[yt == 0], p[yt == 1]

    # AUC without sklearn
    order = np.argsort(p)
    ranks = np.empty(len(p))
    ranks[order] = np.arange(1, len(p) + 1)
    auc = (ranks[yt == 1].sum() - len(mal) * (len(mal) + 1) / 2) / (len(mal) * len(ben))

    thresholds = {}
    report = {"phish": int(len(phish)), "benign": int(len(benign)), "test_phish": int(len(mal)),
              "test_benign": int(len(ben)), "auc": round(float(auc), 5), "best_iteration": model.best_iteration,
              "at_fpr": {}}
    for fpr in FPRS:
        t = threshold_at(ben, fpr)
        thresholds[f"fpr_{fpr:g}"] = t
        report["at_fpr"][f"{fpr:g}"] = {"threshold": round(t, 5), "detection": round(float((mal >= t).mean()), 4),
                                        "false_positives": int((ben >= t).sum())}
    imp = sorted(zip(F.FEATURES, model.feature_importance("gain")), key=lambda x: -x[1])
    report["top_features"] = [f for f, _ in imp[:12]]

    # examples for the report: the benign names scored highest (what an analyst would see)
    test_names = [n for n, t in zip(names, test) if t]
    top_fp = sorted(((float(s), n) for s, n, l in zip(p, test_names, yt) if l == 0), reverse=True)[:15]
    report["highest_benign"] = [[n, round(s, 4)] for s, n in top_fp]
    print(json.dumps(report, indent=1), flush=True)

    # final model on everything, same rounds
    full = lgb.train(params, lgb.Dataset(X, y, feature_name=list(F.FEATURES)),
                     num_boost_round=model.best_iteration or 300)
    dump = full.dump_model()
    out = {"format": 1, "kind": "phishing_domain", "feature_version": F.FEATURE_VERSION,
           "features": list(F.FEATURES), "thresholds": thresholds, "trees": dump["tree_info"],
           "report": report}
    with gzip.open(a.out, "wt", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"))

    # parity samples: the Python scorer must give LightGBM's scores
    rng = random.Random(1)
    idx = rng.sample(range(len(names)), 200)
    par = [{"name": names[i], "score": float(s)} for i, s in zip(idx, full.predict(X[idx]))]
    with gzip.open(a.out.replace(".json.gz", ".parity.json.gz"), "wt", encoding="utf-8") as f:
        json.dump(par, f)
    if a.report:
        json.dump(report, open(a.report, "w"), indent=1)


if __name__ == "__main__":
    main()
