"""Build EMBER2024-format records (label 0) from the ELF files of Debian packages.

    python ml/v3/elf_benign.py <ember2024 dir> <out .jsonl> [--target 6000] [--release bookworm]

EMBER2024's ELF test set has 6,000 benign files, too few for a 0.01% threshold
(it needs 10,000). Needs thrember (github.com/FutureComputing4AI/EMBER2024). Files of the official Debian archive are benign by origin.
The records come from thrember's own extractor (pe=None, as for EMBER2024's ELF
files: only the general, histogram, byteentropy and strings groups are filled),
so ml/v3/train.py reads them like the dataset's. Files whose SHA-256 is in
EMBER2024's ELF_train / ELF_test are skipped, and duplicates are kept once.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import sys
import tarfile
import urllib.request
import zipfile
from multiprocessing import Pool

MIRROR = "https://deb.debian.org/debian"
MAX_FILE = 20 * 1024 * 1024


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "elf-benign-builder"}), timeout=120) as r:
        return r.read()


def packages(release: str) -> list[tuple[str, str]]:
    """(name, pool path) of main/amd64, in a fixed pseudo-random order."""
    text = lzma.decompress(fetch(f"{MIRROR}/dists/{release}/main/binary-amd64/Packages.xz")).decode("utf-8", "replace")
    out = []
    for block in text.split("\n\n"):
        name = path = ""
        for line in block.splitlines():
            if line.startswith("Package: "):
                name = line[9:]
            elif line.startswith("Filename: "):
                path = line[10:]
        if name and path:
            out.append((name, path))
    out.sort(key=lambda p: hashlib.sha256(p[0].encode()).hexdigest())
    return out


def deb_data(deb: bytes) -> tarfile.TarFile | None:
    """The data.tar member of a .deb (ar archive); only gz and xz."""
    if deb[:8] != b"!<arch>\n":
        return None
    at = 8
    while at + 60 <= len(deb):
        name = deb[at:at + 16].decode("ascii", "replace").strip()
        size = int(deb[at + 48:at + 58].decode().strip())
        body = deb[at + 60:at + 60 + size]
        at += 60 + size + (size & 1)
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                body = lzma.decompress(body)
            elif not name.endswith(".gz") and name != "data.tar":
                return None  # zst, bz2: not read
            return tarfile.open(fileobj=io.BytesIO(body), mode="r:*")
    return None


def _extract(task):
    """All ELF files of one package, as (sha256, bytes)."""
    name, path = task
    try:
        tf = deb_data(fetch(f"{MIRROR}/{path}"))
        if tf is None:
            return name, []
        found = []
        for m in tf:
            if not m.isreg() or m.size < 64 or m.size > MAX_FILE:
                continue
            data = tf.extractfile(m).read()
            if data[:4] == b"\x7fELF":
                found.append(data)
        return name, found
    except Exception as e:  # network or archive problems: skip the package
        print(f"skip {name}: {e}", file=sys.stderr, flush=True)
        return name, []


_ext = None


def _record(data: bytes) -> dict | None:
    global _ext
    if _ext is None:
        try:
            from signify.authenticode import SignedPEFile  # noqa: F401
        except ImportError:
            # newer signify renamed it; Authenticode is only read for PE files (never here)
            import types
            import signify.authenticode as sa
            sa.SignedPEFile = types.new_class("SignedPEFile")
        from thrember.features import PEFeatureExtractor
        _ext = PEFeatureExtractor()
    try:
        rec = _ext.raw_features(data)
    except Exception:
        return None
    rec.update({"label": 0, "file_type": "ELF", "family": "", "source": "debian"})
    return rec


def known_shas(data_dir: str) -> set[str]:
    seen = set()
    for z in ("ELF_train.zip", "ELF_test.zip"):
        with zipfile.ZipFile(os.path.join(data_dir, z)) as zf:
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                with zf.open(member) as f:
                    for line in f:
                        seen.add(json.loads(line).get("sha256", ""))
    return seen


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--target", type=int, default=6000)
    ap.add_argument("--release", default="bookworm")
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()

    seen = known_shas(args.data)
    print(f"{len(seen)} EMBER2024 ELF hashes to skip", flush=True)
    pkgs = packages(args.release)
    print(f"{len(pkgs)} packages in {args.release}/main/amd64", flush=True)

    count, batch = 0, 0
    with open(args.out, "w") as out, Pool(args.workers) as pool:
        while count < args.target and batch * 60 < len(pkgs):
            chunk = pkgs[batch * 60:(batch + 1) * 60]
            batch += 1
            files = []
            for _, found in pool.imap_unordered(_extract, chunk):
                for data in found:
                    sha = hashlib.sha256(data).hexdigest()
                    if sha not in seen:
                        seen.add(sha)
                        files.append(data)
            for rec in pool.imap_unordered(_record, files, chunksize=8):
                if rec is not None:
                    out.write(json.dumps(rec) + "\n")
                    count += 1
            out.flush()
            print(f"{batch * 60} packages, {count} ELF files", flush=True)
    print("wrote", args.out, count)


if __name__ == "__main__":
    main()
