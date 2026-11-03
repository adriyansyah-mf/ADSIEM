"""Check the Go v3 vector equals ml/v3/vectorize.py's on the same raw features.

    python3 ml/v3/compare_vectors.py go.jsonl   (from TestDumpV3)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from vectorize import DIM, GROUPS, vector  # noqa: E402


def group_of(i):
    at = 0
    for name, n in GROUPS:
        if i < at + n:
            return name
        at += n
    return "?"


def main(path):
    bad, n = 0, 0
    for line in open(path):
        rec = json.loads(line)
        py, go = vector(rec["raw"]), rec["vector"]
        n += 1
        diffs = [i for i in range(DIM) if abs(py[i] - go[i]) > 1e-6 * max(1.0, abs(py[i]), abs(go[i]))]
        if diffs or len(go) != DIM:
            bad += 1
            if bad <= 5:
                i = diffs[0] if diffs else -1
                print(os.path.basename(rec["file"]), len(diffs), "differ, first", i, group_of(i), py[i], go[i])
    print(f"vector parity: {n - bad}/{n} equal")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
