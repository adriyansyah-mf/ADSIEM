#!/usr/bin/env python3
"""Record libyara's results for cases.yaml into expected.json.

The Go differential test compares the pure-Go engine against this file.
Regenerate after editing cases.yaml:

    uv venv /tmp/yref && uv pip install --python /tmp/yref/bin/python yara-python pyyaml
    /tmp/yref/bin/python gen_expected.py

The libyara version used is stored in the output.
"""
import json
import os
import sys

import yara
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def load_input(spec):
    if spec.startswith("hex:"):
        return bytes.fromhex(spec[4:])
    if spec.startswith("rep:"):
        return b"".join(s.encode("latin-1") * n for s, n in json.loads(spec[4:]))
    if spec.startswith("file:"):
        with open(os.path.join(HERE, "fixtures", spec[5:]), "rb") as f:
            return f.read()
    return spec.encode("latin-1")


def main():
    cases = []
    for name in sorted(os.listdir(HERE)):
        if name.startswith("cases") and name.endswith(".yaml"):
            with open(os.path.join(HERE, name)) as f:
                cases += yaml.safe_load(f)
    out = {"libyara": yara.__version__, "cases": {}}
    for case in cases:
        name = case["name"]
        try:
            rules = yara.compile(source=case["rules"])
        except yara.Error as e:
            out["cases"][name] = {"error": str(e)}
            continue
        results = []
        for spec in case["inputs"]:
            matches = []
            for m in rules.match(data=load_input(spec)):
                strings = []
                for s in m.strings:
                    for inst in s.instances:
                        strings.append([s.identifier, inst.offset, inst.matched_length])
                strings.sort(key=lambda x: (x[0], x[1]))
                matches.append({"rule": m.rule, "strings": strings})
            matches.sort(key=lambda m: m["rule"])
            results.append(matches)
        out["cases"][name] = {"results": results}
    out["modules"] = dump_modules()
    with open(os.path.join(HERE, "expected.json"), "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{len(cases)} cases, libyara {yara.__version__}", file=sys.stderr)


def plain(v):
    """Module data as JSON: bytes become Latin-1 strings."""
    if isinstance(v, bytes):
        return v.decode("latin-1")
    if isinstance(v, dict):
        return {k: plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v


def dump_modules():
    """The pe and elf module data libyara builds for each fixture."""
    rules = yara.compile(source='import "pe" import "elf" rule dump { condition: true }')
    dumps = {}
    fixtures = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(fixtures)):
        path = os.path.join(fixtures, name)
        if not os.path.isfile(path) or name.endswith(".sh"):
            continue
        got = {}

        def cb(data, got=got):
            got[data["module"]] = plain({k: v for k, v in data.items() if k != "module"})
            return yara.CALLBACK_CONTINUE

        with open(path, "rb") as f:
            rules.match(data=f.read(), modules_callback=cb)
        dumps[name] = got
    return dumps


if __name__ == "__main__":
    main()
