#!/bin/sh
# fetch-release.sh VERSION [DIR]: serve the release's packages instead of the
# local build. The deb/rpm/msi (and their .sig) of GitHub release
# agent-v$VERSION replace the locally built deb/rpm in DIR (dist/packages):
# they were signed by the release workflow with AGENT_UPDATE_SIGNING_KEY,
# which never leaves GitHub, and their agents trust AGENT_UPDATE_PUBLIC_KEYS,
# so self-update works without the signing key on this server.
#
# Without a release for VERSION (an unreleased build, GitHub unreachable) the
# local packages stay: they install fine but are unsigned, and agents built
# here trust no update key unless UPDATE_KEYS was passed to the build.
#
# The release's Windows zip replaces the local one too, so every package the
# dashboard serves comes from the same signed release build.
#
# FETCH_REQUIRE_FULL=1 (build-packages.sh, before any local build): succeed
# only when the release has everything the local build would produce (amd64
# deb, x86_64 rpm, Windows amd64 zip); otherwise change nothing and exit 3 so
# the caller builds locally.
set -eu
v="$1"
out="${2:-dist/packages}"
repo="${AGENT_REPO:-adriyansyah-mf/ADSIEM}"
api="${GITHUB_API:-https://api.github.com}/repos/${repo}/releases/tags/agent-v${v}"

# A stalled transfer must not hang the image build: bounded and retried,
# then the local packages are served.
# --retry-all-errors: a reset connection (curl 35/56, common on GitHub's
# asset CDN) is retried too, not only timeouts and 5xx.
fetch() { curl -fsSL --connect-timeout 20 --max-time 300 --retry 5 --retry-delay 2 --retry-all-errors "$@"; }

keep_local() {
  if [ "${FETCH_REQUIRE_FULL:-}" = 1 ]; then
    echo "fetch-release: $1; building locally" >&2
    exit 3
  fi
  echo "fetch-release: $1; serving the locally built, UNSIGNED packages (no self-update from them)" >&2
  exit 0
}

meta="$(mktemp)"
fetch "$api" -o "$meta" || { rm -f "$meta"; keep_local "no release agent-v${v} on ${repo}"; }
urls="$(grep -o '"browser_download_url": *"[^"]*"' "$meta" | sed 's/.*"\(http[^"]*\)"$/\1/' |
  grep -E '/siem-agent[^/]*\.(deb|rpm|msi|zip)(\.sig)?$' || true)"
rm -f "$meta"
[ -n "$urls" ] || keep_local "release agent-v${v} has no deb/rpm/msi"
if [ "${FETCH_REQUIRE_FULL:-}" = 1 ]; then
  for want in "siem-agent_${v}_amd64.deb" "siem-agent-${v}-1.x86_64.rpm" "siem-agent-windows-amd64-${v}.zip"; do
    printf '%s\n' "$urls" | grep -q "/${want}\$" || keep_local "release agent-v${v} has no ${want}"
  done
fi

dl="$(mktemp -d)"
for u in $urls; do
  fetch -o "$dl/$(basename "$u")" "$u" || { rm -rf "$dl"; keep_local "download of $(basename "$u") failed"; }
done
if ! ls "$dl"/*.sig >/dev/null 2>&1; then
  echo "fetch-release: warning: release agent-v${v} is unsigned (its workflow ran without AGENT_UPDATE_SIGNING_KEY): it installs, but is never offered as an update" >&2
fi
mkdir -p "$out"
rm -f "$out"/siem-agent*.deb "$out"/siem-agent*.rpm "$out"/siem-agent*.msi "$out"/siem-agent*.sig
if ls "$dl"/siem-agent-windows-*.zip >/dev/null 2>&1; then
  rm -f "$out"/siem-agent-windows-*.zip
fi
cp "$dl"/* "$out"/
rm -rf "$dl"
echo "fetch-release: serving release agent-v${v}: $(cd "$out" && ls | tr '\n' ' ')"
