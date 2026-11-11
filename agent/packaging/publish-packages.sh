#!/bin/sh
# package-builder's CMD: publish dist/packages into /output (the agent_packages
# volume). The deploy wizard serves the top level, so only this build goes
# there; signed packages of earlier builds move to /output/archive, where
# self-update still finds them, so a rollout can roll back to them.
set -eu
out="${OUTPUT_DIR:-/output}"
# The image was built before its release was complete (the tag pushed, the
# release workflow still running): Docker caches that layer, so rebuilding
# never looks again and every run would publish the same unsigned local
# build, which the dashboard never offers. Look again now.
if ! ls dist/packages/*.sig >/dev/null 2>&1 && [ -z "${SIEM_UPDATE_SIGNING_KEY:-}" ] && [ -f VERSION ]; then
  if FETCH_REQUIRE_FULL=1 sh packaging/fetch-release.sh "$(cat VERSION)" dist/packages; then
    echo "publish-packages: the image held an unsigned build; serving release agent-v$(cat VERSION) instead"
  else
    echo "publish-packages: release agent-v$(cat VERSION) still incomplete; publishing the UNSIGNED local build" >&2
  fi
fi
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
