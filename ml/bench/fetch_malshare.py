"""Download malware samples from MalShare for the detection benchmark.

    MALSHARE_KEY=... python3 ml/bench/fetch_malshare.py <out dir> --days 2026-01-01,2025-12-15 --max 1500

MalShare's daily lists (https://malshare.com/daily/<day>/) name every sample
it received that day; a random subset (fixed seed) is fetched with the API
(action=getfile, one request each; the default key allows 2000 a day).

MalShare serves raw files. Each one is piped straight into `zip -P infected`
(ZipCrypto, the format agent/cmd/detbench and MalwareBazaar use): the raw
sample is never written to disk and never run. Its SHA-256 is checked
before the zip is kept. Writes <sha256>.zip and manifest.jsonl (MalwareBazaar's
field names; file_type from the first bytes, signature empty: MalShare has
no family labels, and tags ["malshare", <day>]). Already downloaded samples
are skipped. Use a machine with no shared or synced folders.

MalShare's terms apply to what you download. The key is read from the
environment only and is never written anywhere.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

API = "https://malshare.com/api.php"
DAILY = "https://malshare.com/daily/{day}/malshare_fileList.{day}.sha256.txt"
UA = {"User-Agent": "adsiem-detbench"}


def http(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def api(key: str, **params) -> bytes:
    q = urllib.parse.urlencode({"api_key": key, **params})
    return http(f"{API}?{q}")


def file_type(b: bytes) -> str:
    """A MalwareBazaar-style file_type from the first bytes."""
    if b[:2] == b"MZ":
        try:
            pe = struct.unpack_from("<I", b, 0x3C)[0]
            if b[pe:pe + 4] == b"PE\0\0":
                chars = struct.unpack_from("<H", b, pe + 22)[0]
                return "dll" if chars & 0x2000 else "exe"
        except struct.error:
            pass
        return "exe"
    if b[:4] == b"\x7fELF":
        return "elf"
    head = b[:4096].lstrip().lower()
    for magic, kind in ((b"pk\x03\x04", "zip"), (b"rar!", "rar"), (b"7z\xbc\xaf", "7z"), (b"\x1f\x8b", "gz"),
                        (b"\xd0\xcf\x11\xe0", "ole"), (b"%pdf", "pdf"), (b"{\\rtf", "rtf"),
                        (b"l\x00\x00\x00\x01\x14\x02", "lnk"), (b"mscf", "cab")):
        if b[:len(magic)].lower() == magic:
            return kind
    if head.startswith(b"<?php") or b"<?php" in head:
        return "php"
    if head.startswith(b"#!"):
        line = head.split(b"\n", 1)[0]
        return "py" if b"python" in line else "sh"
    if head.startswith((b"<!doctype html", b"<html")) or b"<script" in head:
        return "html"
    if b"powershell" in head or b"invoke-" in head or b"-encodedcommand" in head:
        return "ps1"
    if b"createobject(" in head or b"wscript." in head:
        return "vbs"
    return "unknown"


def zip_sample(data: bytes, path: str) -> None:
    """Writes data as the one entry of a ZipCrypto zip (password "infected"),
    through zip's stdin: the raw bytes never touch the disk."""
    tmp = path + ".part"
    if os.path.exists(tmp):
        os.remove(tmp)
    subprocess.run(["zip", "-q", "-P", "infected", tmp, "-"], input=data, check=True)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--days", required=True, help="comma-separated YYYY-MM-DD daily lists to sample from")
    ap.add_argument("--max", type=int, default=1500, help="samples to fetch in total")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--keep-requests", type=int, default=50, help="API requests left unused at the end")
    args = ap.parse_args()
    key = os.environ.get("MALSHARE_KEY", "")
    if not key:
        print("set MALSHARE_KEY", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    manifest = os.path.join(args.out, "manifest.jsonl")
    have = set()
    if os.path.exists(manifest):
        with open(manifest) as f:
            have = {json.loads(l)["sha256_hash"] for l in f if l.strip()}

    pool: list[tuple[str, str]] = []
    for day in args.days.split(","):
        text = http(DAILY.format(day=day)).decode()
        shas = [l.strip() for l in text.splitlines() if len(l.strip()) == 64]
        pool += [(s, day) for s in shas]
        print(f"{day}: {len(shas)} samples listed")
    random.Random(args.seed).shuffle(pool)

    limit = json.loads(api(key, action="getlimit"))
    budget = int(limit.get("REMAINING", 0)) - args.keep_requests
    print(f"API requests left: {limit.get('REMAINING')}, using at most {budget}")
    got, failed, types = 0, 0, {}
    with open(manifest, "a") as man:
        for sha, day in pool:
            if got >= args.max or budget <= 0:
                break
            if sha in have:
                continue
            budget -= 1
            try:
                data = api(key, action="getfile", hash=sha)
            except Exception as e:  # noqa: BLE001 - a failed download is skipped
                failed += 1
                print(f"skip {sha}: {e}", file=sys.stderr)
                continue
            if hashlib.sha256(data).hexdigest() != sha:
                failed += 1  # an error page, or not the file asked for
                continue
            kind = file_type(data)
            zip_sample(data, os.path.join(args.out, sha + ".zip"))
            del data
            man.write(json.dumps({"sha256_hash": sha, "file_type": kind, "signature": None, "first_seen": day,
                                  "tags": ["malshare", day]}) + "\n")
            man.flush()
            got += 1
            types[kind] = types.get(kind, 0) + 1
            if got % 100 == 0:
                print(f"{got} fetched {types}")
            time.sleep(0.2)
    print(f"done: {got} fetched, {failed} failed, by type {types}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
