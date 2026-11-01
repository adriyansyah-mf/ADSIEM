#!/bin/sh
# package-builder's CMD: publish dist/packages into /output (the agent_packages
# volume). The deploy wizard serves the top level, so only this build goes
# there; signed packages of earlier builds move to /output/archive, where
# self-update still finds them, so a rollout can roll back to them.
set -eu
out="${OUTPUT_DIR:-/output}"
if [ -n "${SIEM_UPDATE_SIGNING_KEY:-}" ]; then
  # never baked into the image: only in the container's environment
  for p in dist/packages/*.deb dist/packages/*.rpm; do
    [ -e "$p" ] && siem-update-sign sign "$p"
  done
fi
mkdir -p "$out/archive"
for sig in "$out"/siem-agent*.sig; do
  [ -e "$sig" ] || continue
  pkg="${sig%.sig}"
  [ -e "$pkg" ] && mv -f "$pkg" "$sig" "$out/archive/"
done
rm -f "$out"/siem-agent*
cp dist/packages/siem-agent* "$out/"
ls -l "$out" "$out/archive"
