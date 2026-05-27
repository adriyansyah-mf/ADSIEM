#!/bin/bash
set -e

VERSION="${VERSION:-1.1.0}"
OUTPUT="${OUTPUT:-/output}"
mkdir -p "$OUTPUT"

echo "Cross-compiling siem-agent for Windows (v${VERSION})..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /tmp/siem-agent.exe \
    /src/cmd/agent/

# Create zip package
ZIPDIR="/tmp/siem-agent-windows-${VERSION}"
mkdir -p "$ZIPDIR"
cp /tmp/siem-agent.exe "$ZIPDIR/"
cp /src/packaging/install-windows.ps1 "$ZIPDIR/"
cat > "$ZIPDIR/config.yaml.template" << 'EOF'
agent:
  name: "my-agent"
  group: "default"

server:
  url: "REPLACE_WITH_SERVER_URL"
  heartbeat_interval: 30

logs: []
EOF

ZIP_OUT="$OUTPUT/siem-agent-${VERSION}-windows-amd64.zip"
cd /tmp && zip -r "$ZIP_OUT" "siem-agent-windows-${VERSION}/"
echo "✓ Created: $ZIP_OUT ($(du -sh "$ZIP_OUT" | cut -f1))"
