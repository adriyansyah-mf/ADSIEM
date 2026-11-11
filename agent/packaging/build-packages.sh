#!/bin/sh
# build-packages.sh: fill dist/packages for package-builder (Dockerfile.packages).
#
# A released version is served straight from its GitHub release (deb, rpm,
# msi, Windows zip and the .sig files the release workflow made): the local
# build is skipped, because fetch-release.sh would replace its output anyway
# and three full Go builds (deb, rpm, Windows) take minutes on a small server.
# Anything else (an unreleased version, an incomplete release, GitHub
# unreachable) is built locally, then fetch-release.sh swaps in whatever the
# release does have, exactly as before.
set -eu
v="$(cat VERSION)"
mkdir -p dist/packages

if FETCH_REQUIRE_FULL=1 sh packaging/fetch-release.sh "$v" dist/packages; then
  echo "build-packages: release agent-v${v} served; local build skipped"
  exit 0
else
  rc=$?
  [ "$rc" -eq 3 ] || exit "$rc"
fi

echo "build-packages: building agent ${v} locally"
for obj in \
  "internal/procexec/bpf/execve -I internal/procexec/bpf/include" \
  "internal/netwatch/bpf/netwatch -I internal" \
  "internal/linsensor/bpf/linsensor -I internal" \
  "internal/prevent/bpf/prevent"; do
  # shellcheck disable=SC2086 # the include flags are meant to split
  set -- $obj
  src="$1"
  shift
  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 "$@" -c "${src}.bpf.c" -o "${src}.bpf.o"
done

export VERSION="$v"
bash packaging/build-deb.sh >/dev/null
ARCH=x86_64 bash packaging/build-rpm.sh >/dev/null
ARCH=amd64 bash packaging/build-windows.sh
sh packaging/fetch-release.sh "$v" dist/packages
