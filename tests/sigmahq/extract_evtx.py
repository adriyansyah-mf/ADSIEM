"""SigmaHQ regression, step 1: every regression .evtx → JSONL {rule_id, title, match_count, xml: [...]}.

Usage: extract_evtx.py <sigma checkout> <out.jsonl>   (needs python-evtx)"""
import glob
import json
import os
import sys

import Evtx.Evtx as evtx
import yaml

repo, out = sys.argv[1], sys.argv[2]
n = 0
with open(out, "w") as fh:
    for info_path in sorted(glob.glob(f"{repo}/regression_data/**/info.yml", recursive=True)):
        info = yaml.safe_load(open(info_path))
        meta = (info.get("rule_metadata") or [{}])[0]
        for test in info.get("regression_tests_info") or []:
            if test.get("type") != "evtx":
                continue
            path = os.path.join(repo, test["path"])
            if not os.path.exists(path):
                continue
            try:
                with evtx.Evtx(path) as log:
                    xmls = [rec.xml() for rec in log.records()]
            except Exception as exc:  # noqa: BLE001
                print("unreadable", path, exc, file=sys.stderr)
                continue
            fh.write(json.dumps({"rule_id": meta.get("id"), "title": meta.get("title"),
                                 "test": test.get("name"), "match_count": test.get("match_count", 1),
                                 "xml": xmls}) + "\n")
            n += 1
print("tests", n)
