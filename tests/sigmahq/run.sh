#!/usr/bin/env bash
# SigmaHQ compatibility: replay SigmaHQ's own regression samples (real .evtx
# events, each paired with the rule that must match it) through the exact
# production path — agent formatting (winevent.FormatXML) → repo decoders →
# SigmaEngine with the full SigmaHQ ruleset.
#
#   tests/sigmahq/run.sh [sigma ref]     (default: master; e.g. r2026-07-01)
#
# Needs git, go and python with the worker requirements + python-evtx.
set -euo pipefail

REF="${1:-master}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${SIGMAHQ_WORKDIR:-$(mktemp -d)}"

if [ ! -d "$WORK/sigma/.git" ]; then
  git init -q "$WORK/sigma"
  git -C "$WORK/sigma" remote add origin https://github.com/SigmaHQ/sigma.git
  git -C "$WORK/sigma" sparse-checkout set regression_data rules rules-emerging-threats rules-threat-hunting
fi
git -C "$WORK/sigma" fetch -q --depth 1 origin "$REF"
git -C "$WORK/sigma" checkout -q FETCH_HEAD
echo "SigmaHQ $(git -C "$WORK/sigma" log -1 --format='%h %cs')"

python "$ROOT/tests/sigmahq/extract_evtx.py" "$WORK/sigma" "$WORK/xml.jsonl"
(cd "$ROOT/agent" && go run ./cmd/winevent-fmt) < "$WORK/xml.jsonl" > "$WORK/lines.jsonl"
python "$ROOT/tests/sigmahq/evaluate.py" "$ROOT" "$WORK/sigma" "$WORK/lines.jsonl"
