# tests/evidence/producer.py
"""Log source for the evidence harness: appends COUNT lines to SOURCE at RATE
lines/s, each with a unique marker `evd-<run>-<n>`, flushed and fsynced per
batch so a written line is durable on the source side. Progress (lines
written) goes to SOURCE.progress, which the harness reads to time its faults.
The file is the source of truth for what the agent had to deliver."""
import json
import os
import sys
import time

SOURCE = os.environ.get("SOURCE", "/data/source.log")
RUN = os.environ["EVD_RUN"]
COUNT = int(os.environ.get("EVD_COUNT", "10000"))
RATE = float(os.environ.get("EVD_RATE", "500"))
START = int(os.environ.get("EVD_START", "0"))  # resume numbering for a second batch
BATCH = 50


def marker(n: int) -> str:
    return f"evd-{RUN}-{n:07d}"


def main() -> None:
    progress = SOURCE + ".progress"
    begin = time.monotonic()
    with open(SOURCE, "a", encoding="utf-8") as fh:
        for first in range(START, START + COUNT, BATCH):
            last = min(first + BATCH, START + COUNT)
            for n in range(first, last):
                fh.write(f"Oct 25 10:00:00 evd-host sshd[{n % 30000}]: {marker(n)} Failed password for invalid user u{n % 97}\n")
            fh.flush()
            os.fsync(fh.fileno())
            with open(progress + ".tmp", "w") as p:
                json.dump({"written": last - START, "last": last}, p)
            os.replace(progress + ".tmp", progress)
            due = begin + (last - START) / RATE
            if (wait := due - time.monotonic()) > 0:
                time.sleep(wait)
    print(f"wrote {COUNT} lines", file=sys.stderr)


if __name__ == "__main__":
    main()
