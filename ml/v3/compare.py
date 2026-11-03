"""Compare the agent's v3 raw features (Go dump) with ml/v3/reference.py.

    cd agent && MLSCORE_V3_LIST=list.txt MLSCORE_V3_OUT=go.jsonl go test -run TestDumpV3 ./internal/mlscore
    python3 ml/v3/compare.py go.jsonl [--show 3]

Reports, per feature group, how many files differ, with examples.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from reference import raw as reference_raw  # noqa: E402


def close(a, b, tol=1e-6):
    return abs(float(a) - float(b)) <= tol * max(1.0, abs(float(a)), abs(float(b)))


def same(a, b, tol=1e-6) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k], tol) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(same(x, y, tol) for x, y in zip(a, b))
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) == bool(b)
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if isinstance(a, float) and math.isnan(a):
            return isinstance(b, float) and math.isnan(b)
        return close(a, b, tol)
    return a == b


def norm(go: dict) -> dict:
    """The Go dump's shape -> the reference's (empty groups, int types)."""
    g = dict(go)
    if g.get("header") is None:
        g["header"] = {}
    if g.get("section") is None:
        g["section"] = {}
    if g.get("imports") is None:
        g["imports"] = {}
    if g.get("exports") is None:
        g["exports"] = []
    if g.get("datadirectories") is None:
        g["datadirectories"] = []
    if g.get("richheader") is None:
        g["richheader"] = []
    return g


def diff_detail(group, a, b):
    if group == "section" and a and b:
        sa, sb = a.get("sections", []), b.get("sections", [])
        for i, (x, y) in enumerate(zip(sa, sb)):
            for k in x:
                if not same(x[k], y.get(k), 1e-6):
                    return f"section {i} {k}: go={x[k]!r} ref={y.get(k)!r}"
        if len(sa) != len(sb):
            return f"{len(sa)} sections vs {len(sb)}"
        for k in ("entry", "overlay"):
            if not same(a.get(k), b.get(k)):
                return f"{k}: go={a.get(k)!r} ref={b.get(k)!r}"
    if group == "header" and a and b:
        for part in ("coff", "optional", "dos"):
            for k in b.get(part, {}):
                if not same(a.get(part, {}).get(k), b[part][k]):
                    return f"{part}.{k}: go={a.get(part, {}).get(k)!r} ref={b[part][k]!r}"
    if group == "imports":
        ka, kb = set(a), set(b)
        if ka != kb:
            return f"dlls go-only={sorted(ka - kb)[:3]} ref-only={sorted(kb - ka)[:3]}"
        for k in kb:
            if a[k] != b[k]:
                return f"{k}: go={a[k][:4]}.. ({len(a[k])}) ref={b[k][:4]}.. ({len(b[k])})"
    if group == "strings":
        for k in b:
            if not same(a.get(k), b[k]):
                if k == "string_counts":
                    keys = set(a[k]) | set(b[k])
                    d = {x: (a[k].get(x), b[k].get(x)) for x in keys if a[k].get(x) != b[k].get(x)}
                    return f"string_counts go/ref: {dict(list(d.items())[:4])}"
                return f"{k}: go={a.get(k)!r} ref={b[k]!r}"
    return f"go={str(a)[:160]} ref={str(b)[:160]}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("go_dump")
    ap.add_argument("--show", type=int, default=3)
    args = ap.parse_args()
    bad = Counter()
    examples = defaultdict(list)
    n = 0
    skipped = 0
    for line in open(args.go_dump):
        rec = json.loads(line)
        with open(rec["file"], "rb") as f:
            data = f.read()
        try:
            ref = reference_raw(data)
        except Exception as e:  # pefile itself failed: thrember would too
            skipped += 1
            continue
        if ref.get("imports") is None or ref.get("exports") is None:
            skipped += 1  # thrember fails on non-UTF-8 names: not in the dataset
            continue
        go = norm(rec["raw"])
        n += 1
        for group in ("general", "histogram", "byteentropy", "strings", "header", "section", "imports", "exports",
                      "datadirectories", "richheader"):
            a, b = go.get(group), ref.get(group)
            tol = 1e-5 if group == "strings" else 1e-6
            if not same(a, b, tol):
                bad[group] += 1
                if len(examples[group]) < args.show:
                    examples[group].append(f"{os.path.basename(rec['file'])}: {diff_detail(group, a, b)}")
    print(f"{n} files compared ({skipped} skipped: pefile/thrember would fail)")
    for group in ("general", "histogram", "byteentropy", "strings", "header", "section", "imports", "exports",
                  "datadirectories", "richheader"):
        print(f"{group:16s} {n - bad[group]:6d}/{n} equal")
        for e in examples[group]:
            print("     ", e[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())
