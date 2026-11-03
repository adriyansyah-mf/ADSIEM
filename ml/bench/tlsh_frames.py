"""Stream benchmark samples with their published TLSH to the Go TLSH check.

    python3 ml/bench/tlsh_frames.py <samples dir> | TLSH_STDIN=1 ./tlsh.test -test.run VerifyStdin -test.v

Each sample is decrypted in memory from its zip (password "infected") and
written to stdout as a JSON header line {"sha256", "tlsh", "n"} plus n bytes.
Nothing is written to disk. Samples without a published TLSH are skipped.
"""
import glob
import hashlib
import json
import os
import sys
import zipfile


def main(d: str) -> None:
    man = {}
    with open(os.path.join(d, "manifest.jsonl")) as f:
        for line in f:
            row = json.loads(line)
            man[row["sha256_hash"]] = row
    out = sys.stdout.buffer
    for z in sorted(glob.glob(os.path.join(d, "*.zip"))):
        sha = os.path.basename(z)[:-4]
        published = (man.get(sha) or {}).get("tlsh")
        if not published:
            continue
        with zipfile.ZipFile(z) as zf:
            for info in zf.infolist():
                data = zf.read(info, pwd=b"infected")
                if hashlib.sha256(data).hexdigest() == sha:
                    out.write(json.dumps({"sha256": sha, "tlsh": published, "n": len(data)}).encode() + b"\n")
                    out.write(data)
                    break
    out.flush()


if __name__ == "__main__":
    main(sys.argv[1])
