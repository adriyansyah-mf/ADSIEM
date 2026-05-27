#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${VERSION:-1.1.0}"
ARCH="${ARCH:-$(uname -m)}"   # x86_64, aarch64, etc.

# Map uname -m to GOARCH
case "$ARCH" in
  x86_64)  GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
  armv7l)  GOARCH=arm   ;;
  i686)    GOARCH=386   ;;
  *)       GOARCH=amd64 ;;
esac

RPMBUILD_ROOT="${HOME}/rpmbuild"

echo "==> Building binary (GOOS=linux GOARCH=${GOARCH})"
cd "$AGENT_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" go build \
  -ldflags="-s -w -X github.com/siem-platform/agent/internal/version.Version=${VERSION}" \
  -o "dist/siem-agent-${GOARCH}" \
  ./cmd/agent/

echo "==> Setting up rpmbuild tree"
mkdir -p "${RPMBUILD_ROOT}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy sources that the spec installs
cp "dist/siem-agent-${GOARCH}"        "${RPMBUILD_ROOT}/SOURCES/siem-agent"
cp "packaging/siem-agent.service"      "${RPMBUILD_ROOT}/SOURCES/siem-agent.service"
cp "packaging/config.yaml"             "${RPMBUILD_ROOT}/SOURCES/config.yaml"
cp "packaging/siem-agent.spec"         "${RPMBUILD_ROOT}/SPECS/siem-agent.spec"

echo "==> Building .rpm"
rpmbuild -bb \
  --define "_version ${VERSION}" \
  --define "_build_arch ${ARCH}" \
  --define "_topdir ${RPMBUILD_ROOT}" \
  "${RPMBUILD_ROOT}/SPECS/siem-agent.spec"

echo "==> Copying output"
mkdir -p "${AGENT_DIR}/dist/packages"
find "${RPMBUILD_ROOT}/RPMS" -name "siem-agent-*.rpm" \
  -exec cp {} "${AGENT_DIR}/dist/packages/" \;

echo "==> Done:"
ls -lh "${AGENT_DIR}/dist/packages/"*.rpm
rpm -qip "${AGENT_DIR}/dist/packages/"siem-agent-*.rpm | head -20
