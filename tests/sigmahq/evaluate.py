"""SigmaHQ regression, step 3: run the agent's lines through the repo decoders and the
SigmaEngine loaded with the whole SigmaHQ ruleset, and compare each rule's match
count with the regression data's expectation.

Usage: evaluate.py <repo root> <sigma checkout> <lines.jsonl>
Exits non-zero when a rule is rejected or a test misses or over-matches
(apart from KNOWN_OVER, where the sample holds more matching events than the
reference count says).
"""
import asyncio
import collections
import glob
import json
import re
import sys

repo, sigma, lines_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, repo + "/worker")
import yaml  # noqa: E402

from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

# Channel → log_type, as configured by agent/packaging/windows/config.yaml;
# any other channel arrives as a generic Windows event log.
CHANNEL_LOG_TYPE = {
    "Security": "windows_security", "System": "windows_system", "Application": "windows_application",
    "Microsoft-Windows-Sysmon/Operational": "windows_sysmon",
    "Microsoft-Windows-PowerShell/Operational": "windows_powershell",
}
CHANNEL_RE = re.compile(r'Channel="([^"]*)"')

# Both events in these samples satisfy the rule; the reference count is 1.
KNOWN_OVER = {
    "Suspicious Kernel Dump Using Dtrace",
    "Github Self-Hosted Runner Execution",
}


def main() -> int:
    decoders = sorted((open(p).read() for p in glob.glob(repo + "/decoders/*.yaml")),
                      key=lambda c: yaml.safe_load(c).get("priority", 100))
    dec = DecoderEngine()
    dec.load_from_yaml_list(decoders)
    files = [f for d in ("rules", "rules-emerging-threats", "rules-threat-hunting")
             for f in glob.glob(f"{sigma}/{d}/**/*.yml", recursive=True)]
    eng = SigmaEngine()
    eng.load_from_yaml_list([open(f).read() for f in files])
    by_id = {r.id: r for r in eng.rules}
    print(f"SigmaHQ rules loaded={len(eng.rules)} rejected={len(eng.load_errors)}")
    for title, err in eng.load_errors:
        print(f"  REJECTED {title}: {err}")

    results: collections.Counter = collections.Counter()
    failures = []

    async def run():
        for raw in open(lines_path):
            rec = json.loads(raw)
            rid = rec["rule_id"]
            if rid not in by_id:
                results["rule not in ruleset"] += 1
                continue
            hits = 0
            for line in rec["lines"]:
                m = CHANNEL_RE.search(line)
                log_type = CHANNEL_LOG_TYPE.get(m.group(1) if m else "", "windows_eventlog")
                event = {**dec.decode(log_type, line), "raw_message": line, "log_type": log_type, "hostname": "h"}
                if any(x["id"] == rid for x in await eng.evaluate(event)):
                    hits += 1
            want = rec["match_count"]
            if hits == want:
                results["pass"] += 1
            elif hits > want and rec["title"] in KNOWN_OVER:
                results["known over-match"] += 1
            else:
                results["miss" if hits < want else "over-match"] += 1
                ls = by_id[rid].logsource
                failures.append(f"{rec['title']} [{ls.get('category') or ls.get('service')}]: {hits} vs {want}")

    asyncio.run(run())
    print(f"regression tests={sum(results.values())} " + " ".join(f"{k}={v}" for k, v in results.most_common()))
    for f in failures:
        print("  FAIL", f)
    return 1 if failures or eng.load_errors else 0


if __name__ == "__main__":
    sys.exit(main())
