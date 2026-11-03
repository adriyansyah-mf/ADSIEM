"""Feature vector for the static PE model, from EMBER-shaped raw features.

The same vector is built by the agent in Go (agent/internal/mlscore/vector.go)
from features it extracts itself; tests/ml/test_vector_parity.py checks the
two agree on the same raw features. Hashing is FNV-1a 32-bit (simple to
reproduce exactly in Go), never sklearn's FeatureHasher.

Layout (DIM floats):
  histogram 256 | byteentropy 256 | strings 104 | general 10 | header 62 |
  section 255 | imports 1280 | exports 128 | datadirectories 30
"""
from __future__ import annotations

import math

HIST, BYTEENT, STRINGS, GENERAL, HEADER, SECTION, IMPORTS, EXPORTS, DATADIRS = \
    256, 256, 104, 10, 62, 255, 1280, 128, 30
DIM = HIST + BYTEENT + STRINGS + GENERAL + HEADER + SECTION + IMPORTS + EXPORTS + DATADIRS


def fnv1a(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode("utf-8", "surrogatepass"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hashed(values: dict[str, float] | list[str], n: int) -> list[float]:
    """Buckets of n: a list counts each string, a dict adds each value."""
    out = [0.0] * n
    if isinstance(values, dict):
        for k, v in values.items():
            out[fnv1a(k) % n] += float(v)
    else:
        for k in values:
            out[fnv1a(k) % n] += 1.0
    return out


def _norm(counts: list[float]) -> list[float]:
    total = float(sum(counts))
    return [c / total for c in counts] if total > 0 else [0.0] * len(counts)


def _strings(s: dict) -> list[float]:
    head = [float(s.get(k, 0)) for k in ("numstrings", "avlength", "printables", "entropy",
                                          "paths", "urls", "registry", "MZ")]
    return head + _norm([float(x) for x in s.get("printabledist", [0] * 96)])


def _general(g: dict) -> list[float]:
    return [float(g.get(k, 0)) for k in ("size", "vsize", "has_debug", "exports", "imports", "has_relocations",
                                         "has_resources", "has_signature", "has_tls", "symbols")]


def _header(h: dict) -> list[float]:
    coff, opt = h.get("coff", {}), h.get("optional", {})
    out = [float(coff.get("timestamp", 0))]
    out += hashed([coff.get("machine", "")], 10)
    out += hashed(list(coff.get("characteristics", [])), 10)
    out += hashed([opt.get("subsystem", "")], 10)
    out += hashed(list(opt.get("dll_characteristics", [])), 10)
    out += hashed([opt.get("magic", "")], 10)
    out += [float(opt.get(k, 0)) for k in (
        "major_image_version", "minor_image_version", "major_linker_version", "minor_linker_version",
        "major_operating_system_version", "minor_operating_system_version", "major_subsystem_version",
        "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_heap_commit")]
    return out  # 1 + 50 + 11 = 62


def _section(s: dict) -> list[float]:
    secs = s.get("sections", [])
    general = [
        float(len(secs)),
        float(sum(1 for x in secs if x.get("size", 0) == 0)),
        float(sum(1 for x in secs if x.get("name", "") == "")),
        float(sum(1 for x in secs if "MEM_READ" in x.get("props", []) and "MEM_EXECUTE" in x.get("props", []))),
        float(sum(1 for x in secs if "MEM_WRITE" in x.get("props", []))),
    ]
    sizes = hashed({x.get("name", ""): x.get("size", 0) for x in secs}, 50)
    entropy = hashed({x.get("name", ""): x.get("entropy", 0) for x in secs}, 50)
    vsizes = hashed({x.get("name", ""): x.get("vsize", 0) for x in secs}, 50)
    entry_name = hashed([s.get("entry", "")], 50)
    entry = next((x for x in secs if x.get("name", "") == s.get("entry", "")), None)
    entry_props = hashed(list(entry.get("props", [])) if entry else [], 50)
    return general + sizes + entropy + vsizes + entry_name + entry_props  # 5 + 250 = 255


def _imports(imp: dict) -> list[float]:
    libs = sorted({lib.lower() for lib in imp})
    funcs = [lib.lower() + ":" + f for lib, fs in imp.items() for f in fs]
    return hashed(libs, 256) + hashed(funcs, 1024)


def _datadirs(dd: list) -> list[float]:
    out = [0.0] * DATADIRS
    for i, d in enumerate(dd[:15]):
        out[2 * i] = float(d.get("size", 0))
        out[2 * i + 1] = float(d.get("virtual_address", 0))
    return out


def vector(raw: dict) -> list[float]:
    v = (_norm([float(x) for x in raw.get("histogram", [0] * 256)])
         + _norm([float(x) for x in raw.get("byteentropy", [0] * 256)])
         + _strings(raw.get("strings", {}))
         + _general(raw.get("general", {}))
         + _header(raw.get("header", {}))
         + _section(raw.get("section", {}))
         + _imports(raw.get("imports", {}))
         + hashed(list(raw.get("exports", [])), EXPORTS)
         + _datadirs(raw.get("datadirectories", [])))
    assert len(v) == DIM, len(v)
    return [x if math.isfinite(x) else 0.0 for x in v]
