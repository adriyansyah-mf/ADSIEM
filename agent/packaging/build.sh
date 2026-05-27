#!/bin/bash
set -e

VERSION="1.1.0"
OUTPUT="/output"
mkdir -p "$OUTPUT"

ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
echo "Building siem-agent packages (v${VERSION}, ${ARCH})..."

# ── .deb ──────────────────────────────────────────────────────────
DEB_ROOT="/tmp/deb-build"
mkdir -p \
  "$DEB_ROOT/DEBIAN" \
  "$DEB_ROOT/usr/bin" \
  "$DEB_ROOT/etc/siem-agent" \
  "$DEB_ROOT/lib/systemd/system"

cp /tmp/siem-agent "$DEB_ROOT/usr/bin/siem-agent"
chmod 755 "$DEB_ROOT/usr/bin/siem-agent"

cat > "$DEB_ROOT/DEBIAN/control" << EOF
Package: siem-agent
Version: $VERSION
Architecture: $ARCH
Maintainer: SIEM Platform <admin@siem.local>
Description: SIEM Platform log collection agent
 Collects system logs and forwards them to the SIEM platform
 for real-time analysis and threat detection.
EOF

cat > "$DEB_ROOT/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
mkdir -p /etc/siem-agent
if [ ! -f /etc/siem-agent/config.yaml ]; then
  cat > /etc/siem-agent/config.yaml << 'CONF'
agent:
  name: "my-agent"
  group: "default"

server:
  url: "REPLACE_WITH_SERVER_URL"
  heartbeat_interval: 30

logs: []
CONF
fi
systemctl daemon-reload 2>/dev/null || true
POSTINST
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

cat > "$DEB_ROOT/lib/systemd/system/siem-agent.service" << 'SERVICE'
[Unit]
Description=SIEM Platform Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/siem-agent -config /etc/siem-agent/config.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

DEB_OUT="$OUTPUT/siem-agent_${VERSION}_${ARCH}.deb"
dpkg-deb --build "$DEB_ROOT" "$DEB_OUT"
echo "✓ Created: $DEB_OUT ($(du -sh "$DEB_OUT" | cut -f1))"

# Also copy raw binary for remote agent upgrades
cp /tmp/siem-agent "$OUTPUT/siem-agent-${VERSION}-${ARCH}"
chmod 755 "$OUTPUT/siem-agent-${VERSION}-${ARCH}"
echo "✓ Created: $OUTPUT/siem-agent-${VERSION}-${ARCH}"

# ── .rpm ──────────────────────────────────────────────────────────
RPM_ARCH="x86_64"
[ "$ARCH" = "arm64" ] && RPM_ARCH="aarch64"

mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp /tmp/siem-agent /root/rpmbuild/SOURCES/

cat > /root/rpmbuild/SPECS/siem-agent.spec << SPEC
Name:        siem-agent
Version:     $VERSION
Release:     1
Summary:     SIEM Platform log collection agent
License:     MIT
BuildArch:   $RPM_ARCH

%description
Collects system logs and forwards them to the SIEM platform
for real-time analysis and threat detection.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/siem-agent
mkdir -p %{buildroot}/lib/systemd/system
cp %{_sourcedir}/siem-agent %{buildroot}/usr/bin/siem-agent
chmod 755 %{buildroot}/usr/bin/siem-agent

cat > %{buildroot}/lib/systemd/system/siem-agent.service << 'SERVICE'
[Unit]
Description=SIEM Platform Agent
After=network-online.target

[Service]
ExecStart=/usr/bin/siem-agent -config /etc/siem-agent/config.yaml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

%post
mkdir -p /etc/siem-agent
if [ ! -f /etc/siem-agent/config.yaml ]; then
  cat > /etc/siem-agent/config.yaml << 'CONF'
agent:
  name: "my-agent"
  group: "default"
server:
  url: "REPLACE_WITH_SERVER_URL"
  heartbeat_interval: 30
logs: []
CONF
fi
systemctl daemon-reload 2>/dev/null || true

%files
/usr/bin/siem-agent
/lib/systemd/system/siem-agent.service
SPEC

rpmbuild -bb /root/rpmbuild/SPECS/siem-agent.spec 2>&1 | tail -5
RPM_FILE=$(find /root/rpmbuild/RPMS -name "*.rpm" | head -1)
if [ -n "$RPM_FILE" ]; then
  cp "$RPM_FILE" "$OUTPUT/siem-agent-${VERSION}-1.${RPM_ARCH}.rpm"
  echo "✓ Created: $OUTPUT/siem-agent-${VERSION}-1.${RPM_ARCH}.rpm"
fi

# ── Windows ───────────────────────────────────────────────────────
echo ""
echo "Building Windows binary..."
if [ -d /src/cmd/agent ]; then
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
        -ldflags="-s -w -X main.Version=${VERSION}" \
        -o "$OUTPUT/siem-agent-${VERSION}-windows-amd64.exe" \
        /src/cmd/agent/
    echo "✓ Created: $OUTPUT/siem-agent-${VERSION}-windows-amd64.exe"
else
    echo "Windows cross-compile skipped (source not in build context)"
fi

echo ""
echo "Packages ready:"
ls -lh "$OUTPUT"
