"""Check the agent's Go features.

    python ml/compare.py <dump dir from TestDumpForParity>

1. Vectoriser parity (must be exact): vectorize.py on the Go raw features
   gives the Go vector.
2. Structure against LIEF (reported): section names / sizes / virtual sizes
   / entropy, entry section, data directories, export names and the number
   of named imports, read with the lief package by this script.
"""
import glob
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from vectorize import vector  # noqa: E402


def close(a, b, tol=1e-6):
    return abs(float(a) - float(b)) <= tol * max(1.0, abs(float(a)), abs(float(b)))


def lief_reference(path):
    import lief
    b = lief.PE.parse(path)
    if b is None:
        return None
    secs = [{"name": s.name, "size": s.size, "vsize": s.virtual_size, "entropy": s.entropy} for s in b.sections]
    entry = ""
    ep = b.optional_header.addressof_entrypoint
    for s in b.sections:
        if s.virtual_address <= ep < s.virtual_address + max(s.virtual_size, s.size):
            entry = s.name
            break
    dd = [(d.size, d.rva) for d in list(b.data_directories)[:15]]
    named = sum(1 for lib in b.imports for e in lib.entries if not e.is_ordinal)
    exports = sorted(e.name for e in b.get_export().entries if e.name) if b.has_exports else []
    return {"sections": secs, "entry": entry, "dd": dd, "named_imports": named, "exports": exports}


def main(dump: str) -> int:
    bad, checks = 0, {}
    for path in sorted(glob.glob(os.path.join(dump, "*.json"))):
        d = json.load(open(path))
        name = os.path.basename(d["file"])
        pv = vector(d["raw"])
        diffs = [i for i, (a, b) in enumerate(zip(pv, d["vector"])) if not close(a, b)]
        if diffs or len(pv) != len(d["vector"]):
            bad += 1
            print("VECTOR MISMATCH", name, diffs[:10])
        ref = lief_reference(d["file"])
        if ref is None:
            print("lief could not parse", name)
            continue
        go = d["raw"]
        gs = go["section"]["sections"]
        results = {
            "section names": [s["name"] for s in gs] == [s["name"] for s in ref["sections"]],
            "section sizes": [(s["size"], s["vsize"]) for s in gs] == [(s["size"], s["vsize"]) for s in ref["sections"]],
            "section entropy": len(gs) == len(ref["sections"]) and all(
                close(a["entropy"], b["entropy"], 1e-4) for a, b in zip(gs, ref["sections"])),
            "entry section": go["section"]["entry"] == ref["entry"],
            "data directories": [(x["size"], x["virtual_address"]) for x in go["datadirectories"]][:len(ref["dd"])]
            == [(float(a), float(b)) for a, b in ref["dd"]],
            "named imports": go["general"]["imports"] == ref["named_imports"],
            "exports": sorted(go["exports"]) == ref["exports"],
        }
        for k, ok in results.items():
            checks.setdefault(k, []).append(ok)
            if not ok:
                print(f"  {name}: {k} differs")
    print("vector parity:", "OK" if bad == 0 else f"{bad} files differ")
    for k, v in checks.items():
        print(f"{k:18s} {sum(v)}/{len(v)} files equal to LIEF")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
