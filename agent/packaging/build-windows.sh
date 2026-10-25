#!/usr/bin/env bash
# Builds dist/packages/siem-agent-windows-<arch>-<version>.zip: siem-agent.exe
# plus install.ps1 / uninstall.ps1 / config.yaml. Run from agent/.
set -euo pipefail

VERSION="${VERSION:-dev}"
ARCH="${ARCH:-amd64}"
STAGE="dist/windows-${ARCH}"

rm -rf "$STAGE"
mkdir -p "$STAGE" dist/packages
CGO_ENABLED=0 GOOS=windows GOARCH="$ARCH" go build \
  -ldflags="-s -w -X main.Version=${VERSION} -X main.UpdateKeys=${UPDATE_KEYS:-}" \
  -o "$STAGE/siem-agent.exe" ./cmd/agent/
cp packaging/windows/install.ps1 packaging/windows/uninstall.ps1 packaging/windows/config.yaml "$STAGE/"

OUT="$(pwd)/dist/packages/siem-agent-windows-${ARCH}-${VERSION}.zip"
rm -f "$OUT"
(cd "$STAGE" && zip -q -r "$OUT" .)
echo "built $OUT"
