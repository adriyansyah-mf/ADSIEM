#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${VERSION:-1.1.0}"
ARCH="${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"

# Map dpkg arch to GOARCH
case "$ARCH" in
  amd64)   GOARCH=amd64 ;;
  arm64)   GOARCH=arm64 ;;
  armhf)   GOARCH=arm  ;;
  i386)    GOARCH=386   ;;
  *)       GOARCH=amd64 ;;
esac

PKG="siem-agent_${VERSION}_${ARCH}"
STAGE="${AGENT_DIR}/dist/deb/${PKG}"

echo "==> Building binary (GOOS=linux GOARCH=${GOARCH})"
cd "$AGENT_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" go build \
  -ldflags="-s -w -X github.com/siem-platform/agent/internal/version.Version=${VERSION}" \
  -o "dist/siem-agent-${GOARCH}" \
  ./cmd/agent/

echo "==> Staging package layout"
rm -rf "$STAGE"
install -Dm755 "dist/siem-agent-${GOARCH}"              "${STAGE}/usr/bin/siem-agent"
install -Dm644 packaging/siem-agent.service              "${STAGE}/lib/systemd/system/siem-agent.service"
install -Dm644 packaging/config.yaml                     "${STAGE}/etc/siem-agent/config.yaml"
install -d                                               "${STAGE}/var/lib/siem-agent"

echo "==> Writing DEBIAN control files"
install -d "${STAGE}/DEBIAN"

cat > "${STAGE}/DEBIAN/control" <<EOF
Package: siem-agent
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: SIEM Platform <admin@example.com>
Depends: systemd
Section: admin
Priority: optional
Homepage: https://github.com/siem-platform/agent
Description: SIEM Platform log collection agent
 Lightweight agent that tails log files, encodes entries with
 exponential-backoff delivery, and ships them to the SIEM server API.
 Supports automatic enrollment and dynamic log source management.
EOF

cat > "${STAGE}/DEBIAN/conffiles" <<EOF
/etc/siem-agent/config.yaml
EOF

cat > "${STAGE}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  configure)
    # Create service user if missing
    if ! id siem-agent >/dev/null 2>&1; then
      useradd --system --no-create-home --shell /sbin/nologin \
              --home /var/lib/siem-agent siem-agent
    fi
    chown -R siem-agent:siem-agent /var/lib/siem-agent
    chmod 750 /var/lib/siem-agent
    # Agent must write token+id back to config after enrollment
    chown siem-agent:siem-agent /etc/siem-agent/config.yaml
    chmod 600 /etc/siem-agent/config.yaml

    systemctl daemon-reload
    systemctl enable siem-agent.service
    echo "siem-agent installed. Edit /etc/siem-agent/config.yaml then:"
    echo "  sudo systemctl start siem-agent"
    ;;
esac
EOF
chmod 0755 "${STAGE}/DEBIAN/postinst"

cat > "${STAGE}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  remove|upgrade|deconfigure)
    systemctl stop siem-agent.service  2>/dev/null || true
    systemctl disable siem-agent.service 2>/dev/null || true
    ;;
esac
EOF
chmod 0755 "${STAGE}/DEBIAN/prerm"

cat > "${STAGE}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  purge)
    rm -rf /etc/siem-agent /var/lib/siem-agent
    if id siem-agent >/dev/null 2>&1; then
      userdel siem-agent 2>/dev/null || true
    fi
    systemctl daemon-reload
    ;;
esac
EOF
chmod 0755 "${STAGE}/DEBIAN/postrm"

echo "==> Building .deb"
mkdir -p "${AGENT_DIR}/dist/packages"
dpkg-deb --build --root-owner-group "${STAGE}" \
  "${AGENT_DIR}/dist/packages/${PKG}.deb"

echo "==> Done: dist/packages/${PKG}.deb"
dpkg-deb --info "${AGENT_DIR}/dist/packages/${PKG}.deb"
