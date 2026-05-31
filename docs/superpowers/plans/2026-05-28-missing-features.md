# SIEM Missing Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 6 missing features to the SIEM platform: Windows agent, syslog receiver, alert correlation, email notifications, audit log UI, and report export.

**Architecture:** Each feature is independent. Windows agent adds Go build-tag stubs for Linux-only syscalls and a PowerShell installer. Syslog receiver is a new Docker service that parses RFC 3164/5424 and injects directly into the Redis stream the worker already consumes. Alert correlation is a worker-side engine that checks recent alerts after every new alert and fires a meta-alert. Email and webhook share the same trigger points. Audit log and report export are pure CRUD additions to server-api + new React pages.

**Tech Stack:** Go 1.22 (build tags, Windows cross-compile), Python asyncio (syslog UDP/TCP), aiosmtplib (email), reportlab (PDF), FastAPI StreamingResponse (CSV/PDF download), React + TanStack Query (new pages).

---

## File Map

### Task 1 — Windows Agent
- Rename: `agent/internal/task/isolation.go` → `agent/internal/task/isolation_linux.go` (add `//go:build linux`)
- Create: `agent/internal/task/isolation_windows.go` (stubs)
- Modify: `agent/Makefile` (add `build-windows` target)
- Create: `agent/packaging/build-windows.sh` (produces zip artifact)
- Create: `agent/packaging/install-windows.ps1` (PowerShell installer)
- Modify: `agent/packaging/build.sh` (add Windows binary to Docker output)

### Task 2 — Syslog Receiver
- Create: `syslog-receiver/main.py`
- Create: `syslog-receiver/requirements.txt`
- Create: `syslog-receiver/Dockerfile`
- Modify: `docker-compose.yml` (add syslog-receiver service)

### Task 3 — Alert Correlation Engine
- Modify: `server-api/app/models/models.py` (add `CorrelationRule`)
- Modify: `server-api/app/schemas/schemas.py` (add schemas)
- Create: `server-api/app/api/routes/correlation.py`
- Modify: `server-api/app/main.py` (register router, seed default rule)
- Create: `worker/worker/correlation_engine.py`
- Modify: `worker/worker/alert_manager.py` (call correlation check after alert)
- Modify: `worker/worker/models.py` (add CorrelationRule model)
- Create: `dashboard/src/pages/CorrelationPage.tsx`
- Modify: `dashboard/src/App.tsx` (add route)
- Modify: `dashboard/src/components/Sidebar.tsx` (add nav item)

### Task 4 — Email Notifications
- Modify: `worker/requirements.txt` (add aiosmtplib)
- Create: `worker/worker/email_sender.py`
- Modify: `worker/worker/alert_manager.py` (call email after alert)
- Modify: `server-api/app/main.py` (seed SMTP settings)

### Task 5 — Audit Log UI
- Modify: `server-api/app/schemas/schemas.py` (add `AuditLogOut`)
- Create: `server-api/app/api/routes/audit_logs.py`
- Modify: `server-api/app/main.py` (register router)
- Create: `dashboard/src/pages/AuditLogsPage.tsx`
- Modify: `dashboard/src/App.tsx` (add route)
- Modify: `dashboard/src/components/Sidebar.tsx` (add nav item)

### Task 6 — Report Export (CSV + PDF)
- Modify: `server-api/requirements.txt` (add reportlab)
- Create: `server-api/app/api/routes/export.py`
- Modify: `server-api/app/main.py` (register router)
- Modify: `dashboard/src/pages/AlertsPage.tsx` (export button)
- Modify: `dashboard/src/pages/CasesPage.tsx` (export button)

---

## Task 1: Windows Agent Binary + Installer

**Files:**
- Rename: `agent/internal/task/isolation.go` → `agent/internal/task/isolation_linux.go`
- Create: `agent/internal/task/isolation_windows.go`
- Modify: `agent/Makefile`
- Create: `agent/packaging/build-windows.sh`
- Create: `agent/packaging/install-windows.ps1`
- Modify: `agent/packaging/build.sh`

- [ ] **Step 1: Add Linux build tag to isolation.go**

Rename the file and prepend the build constraint:

```bash
cd /home/wonka/Documents/hackathon/agent
mv internal/task/isolation.go internal/task/isolation_linux.go
```

Then add `//go:build linux` as the very first line of `isolation_linux.go`:

```go
//go:build linux

// agent/internal/task/isolation_linux.go
package task

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
)

const isolateChain = "SIEM_ISOLATE"

func isolateHost(serverURL string) error {
	siemIP, err := resolveSIEMIP(serverURL)
	if err != nil {
		return fmt.Errorf("resolve SIEM IP: %w", err)
	}
	exec.Command("iptables", "-N", isolateChain).Run()
	exec.Command("iptables", "-F", isolateChain).Run()
	rules := [][]string{
		{"-A", isolateChain, "-i", "lo", "-j", "ACCEPT"},
		{"-A", isolateChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", isolateChain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", isolateChain, "-d", siemIP, "-j", "ACCEPT"},
		{"-A", isolateChain, "-s", siemIP, "-j", "ACCEPT"},
		{"-A", isolateChain, "-j", "DROP"},
	}
	for _, r := range rules {
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %s", r, out)
		}
	}
	insertJumpIfMissing("INPUT")
	insertJumpIfMissing("OUTPUT")
	return nil
}

func unisolateHost() error {
	exec.Command("iptables", "-D", "INPUT", "-j", isolateChain).Run()
	exec.Command("iptables", "-D", "OUTPUT", "-j", isolateChain).Run()
	exec.Command("iptables", "-F", isolateChain).Run()
	exec.Command("iptables", "-X", isolateChain).Run()
	return nil
}

func insertJumpIfMissing(chain string) {
	if exec.Command("iptables", "-C", chain, "-j", isolateChain).Run() == nil {
		return
	}
	exec.Command("iptables", "-I", chain, "1", "-j", isolateChain).Run()
}

func resolveSIEMIP(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("cannot resolve %s", host)
	}
	return addrs[0], nil
}
```

- [ ] **Step 2: Create Windows stubs**

Create `agent/internal/task/isolation_windows.go`:

```go
//go:build windows

// agent/internal/task/isolation_windows.go
package task

import "fmt"

func isolateHost(_ string) error {
	return fmt.Errorf("network isolation not supported on Windows")
}

func unisolateHost() error {
	return fmt.Errorf("network isolation not supported on Windows")
}
```

- [ ] **Step 3: Verify Linux build still compiles**

```bash
cd /home/wonka/Documents/hackathon/agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/siem-agent-linux-test ./cmd/agent/
echo "exit: $?"
```

Expected: `exit: 0`

- [ ] **Step 4: Verify Windows cross-compile succeeds**

```bash
cd /home/wonka/Documents/hackathon/agent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o /tmp/siem-agent-windows-test.exe ./cmd/agent/
echo "exit: $?"
file /tmp/siem-agent-windows-test.exe
```

Expected: `PE32+ executable (console) x86-64`

- [ ] **Step 5: Add build-windows target to Makefile**

Open `agent/Makefile` and add after the existing `build:` target:

```makefile
VERSION ?= 1.0.0
ARCH    ?= $(shell dpkg --print-architecture 2>/dev/null || uname -m)

.PHONY: build build-windows package-deb package-rpm package clean

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" \
		-o bin/siem-agent ./cmd/agent/

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
		-ldflags="-s -w -X main.Version=$(VERSION)" \
		-o bin/siem-agent.exe ./cmd/agent/

package-deb:
	@mkdir -p dist
	VERSION=$(VERSION) ARCH=$(ARCH) bash packaging/build-deb.sh

package-rpm:
	@mkdir -p dist
	VERSION=$(VERSION) bash packaging/build-rpm.sh

package: package-deb package-rpm

clean:
	rm -rf dist bin
```

- [ ] **Step 6: Create PowerShell installer script**

Create `agent/packaging/install-windows.ps1`:

```powershell
# install-windows.ps1
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install-windows.ps1 -ServerURL http://YOUR_SERVER

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerURL,
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$Group = "default"
)

$InstallDir = "C:\ProgramData\siem-agent"
$BinaryPath = "$InstallDir\siem-agent.exe"
$ConfigPath = "$InstallDir\config.yaml"
$ServiceName = "siem-agent"

# Create install directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Copy binary from same directory as script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$ScriptDir\siem-agent.exe" $BinaryPath -Force

# Write config
@"
agent:
  name: "$AgentName"
  group: "$Group"

server:
  url: "$ServerURL"
  heartbeat_interval: 30

logs:
  - path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
    type: windows_security
    enabled: false
"@ | Set-Content $ConfigPath -Encoding UTF8

# Install Windows service using sc.exe
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

sc.exe create $ServiceName binPath= "`"$BinaryPath`" -config `"$ConfigPath`"" start= auto DisplayName= "SIEM Platform Agent" | Out-Null
sc.exe description $ServiceName "Collects system logs and forwards them to SIEM Platform" | Out-Null
Start-Service -Name $ServiceName

$svc = Get-Service -Name $ServiceName
Write-Host "Service status: $($svc.Status)"
Write-Host "SIEM Agent installed successfully. Config: $ConfigPath"
```

- [ ] **Step 7: Create Windows build script**

Create `agent/packaging/build-windows.sh`:

```bash
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
```

- [ ] **Step 8: Add Windows build to Docker package-builder**

In `agent/packaging/build.sh`, append after the RPM section (before the final `ls` command):

```bash
# ── Windows ───────────────────────────────────────────────────────
echo ""
echo "Building Windows binary..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o "$OUTPUT/siem-agent-${VERSION}-windows-amd64.exe" \
    /src/cmd/agent/ 2>/dev/null || echo "Windows cross-compile skipped (not in build context)"
```

Note: The Docker build context for `package-builder` uses `/tmp/siem-agent` as the pre-built binary; the Windows binary requires the Go source. This step produces the `.exe` only when the full source is available. In the Docker Dockerfile.packages, the source is not copied, so this will skip gracefully.

- [ ] **Step 9: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add agent/internal/task/isolation_linux.go agent/internal/task/isolation_windows.go
git add agent/Makefile agent/packaging/build-windows.sh agent/packaging/install-windows.ps1
git add agent/packaging/build.sh
git commit -m "feat(agent): add Windows build support with Linux-only stubs and PowerShell installer"
```

---

## Task 2: Syslog Receiver Service

**Files:**
- Create: `syslog-receiver/main.py`
- Create: `syslog-receiver/requirements.txt`
- Create: `syslog-receiver/Dockerfile`
- Modify: `docker-compose.yml`

The syslog receiver listens on UDP 514 and TCP 514, parses RFC 3164 and RFC 5424 messages, and publishes them directly to the Redis stream `siem:logs` so the existing worker pipeline processes them without any changes.

- [ ] **Step 1: Create requirements.txt**

Create `syslog-receiver/requirements.txt`:

```
redis==5.2.0
structlog==24.4.0
```

- [ ] **Step 2: Create main.py**

Create `syslog-receiver/main.py`:

```python
#!/usr/bin/env python3
"""
Syslog receiver: UDP/TCP 514 → Redis stream siem:logs
Parses RFC 3164 and RFC 5424. Each message becomes a log entry
identical to those sent by the Go agent, with agent_id="syslog".
"""
import asyncio
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
import structlog

log = structlog.get_logger()

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STREAM_KEY = os.environ.get("REDIS_STREAM_KEY", "siem:logs")
SYSLOG_AGENT_ID = os.environ.get("SYSLOG_AGENT_ID", "00000000-0000-0000-0000-000000000001")

# RFC 3164: <PRI>Mon DD HH:MM:SS hostname tag[pid]: message
_RFC3164 = re.compile(
    r"^<(\d+)>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"         # hostname
    r"(\S+?)(?:\[(\d+)\])?:\s*"  # tag[pid]
    r"(.*)$",
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RFC5424 = re.compile(
    r"^<(\d+)>(\d+)\s+"
    r"(\S+)\s+"   # timestamp
    r"(\S+)\s+"   # hostname
    r"(\S+)\s+"   # app-name
    r"(\S+)\s+"   # procid
    r"(\S+)\s+"   # msgid
    r"(?:\[.*?\]|-)\s*"  # structured-data
    r"(.*)$",
    re.DOTALL,
)

_SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
_FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp",
]


def _parse(raw: str) -> dict | None:
    raw = raw.strip()
    if not raw:
        return None

    m = _RFC5424.match(raw)
    if m:
        pri, _ver, ts, hostname, appname, _pid, _mid, msg = m.groups()
        pri = int(pri)
        return {
            "hostname": hostname if hostname != "-" else "unknown",
            "app": appname if appname != "-" else "syslog",
            "message": msg.strip(),
            "severity": _SEVERITY_NAMES[pri & 7],
            "facility": _FACILITY_NAMES[min((pri >> 3), len(_FACILITY_NAMES) - 1)],
            "timestamp": ts,
        }

    m = _RFC3164.match(raw)
    if m:
        pri, ts, hostname, tag, _pid, msg = m.groups()
        pri = int(pri)
        return {
            "hostname": hostname,
            "app": tag,
            "message": msg.strip(),
            "severity": _SEVERITY_NAMES[pri & 7],
            "facility": _FACILITY_NAMES[min((pri >> 3), len(_FACILITY_NAMES) - 1)],
            "timestamp": ts,
        }

    # Unparsed — wrap raw text
    return {
        "hostname": "unknown",
        "app": "syslog",
        "message": raw,
        "severity": "info",
        "facility": "user",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class _SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self._q = queue

    def datagram_received(self, data: bytes, addr):
        try:
            self._q.put_nowait(data.decode("utf-8", errors="replace"))
        except asyncio.QueueFull:
            pass

    def error_received(self, exc):
        log.warning("udp_error", error=str(exc))


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, queue: asyncio.Queue):
    peer = writer.get_extra_info("peername")
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            queue.put_nowait(line.decode("utf-8", errors="replace"))
    except Exception:
        pass
    finally:
        writer.close()


async def _publish_loop(queue: asyncio.Queue, redis: aioredis.Redis):
    while True:
        raw = await queue.get()
        parsed = _parse(raw)
        if not parsed:
            continue
        entry = {
            "agent_id": SYSLOG_AGENT_ID,
            "log_type": f"syslog_{parsed['facility']}",
            "raw_message": parsed["message"],
            "received_at": datetime.now(timezone.utc).isoformat(),
            "hostname": parsed["hostname"],
        }
        try:
            await redis.xadd(STREAM_KEY, {"data": json.dumps(entry)})
        except Exception as exc:
            log.error("redis_publish_failed", error=str(exc))


async def main():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    loop = asyncio.get_running_loop()

    # UDP listener
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _SyslogProtocol(queue),
        local_addr=("0.0.0.0", 514),
    )
    log.info("syslog_udp_listening", port=514)

    # TCP listener
    tcp_server = await asyncio.start_server(
        lambda r, w: _tcp_handler(r, w, queue),
        "0.0.0.0", 514,
    )
    log.info("syslog_tcp_listening", port=514)

    log.info("syslog_receiver_started", redis=REDIS_URL, stream=STREAM_KEY)

    try:
        await asyncio.gather(
            _publish_loop(queue, redis),
            tcp_server.serve_forever(),
        )
    finally:
        transport.close()
        tcp_server.close()


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 3: Create Dockerfile**

Create `syslog-receiver/Dockerfile`:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
CMD ["python", "main.py"]
```

- [ ] **Step 4: Add service to docker-compose.yml**

Open `docker-compose.yml` and add after the `worker:` service block (before `nginx:` or `searxng:`):

```yaml
  syslog-receiver:
    build:
      context: ./syslog-receiver
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - "514:514/udp"
      - "514:514/tcp"
    environment:
      REDIS_URL: ${REDIS_URL:-redis://redis:6379/0}
      REDIS_STREAM_KEY: ${REDIS_STREAM_KEY:-siem:logs}
    depends_on:
      redis:
        condition: service_healthy
    networks:
      - siem-net
```

- [ ] **Step 5: Test syslog receiver locally**

```bash
cd /home/wonka/Documents/hackathon
pip install redis structlog --quiet
# Test the parser directly
python3 -c "
import sys; sys.path.insert(0, 'syslog-receiver')
from main import _parse
print(_parse('<34>Oct 11 22:14:15 mymachine su: failed login'))
print(_parse('<165>1 2003-10-11T22:14:15.003Z mymachine sshd 2 - - Failed password'))
"
```

Expected: both lines return dicts with `hostname`, `app`, `message`, `severity`, `facility`.

- [ ] **Step 6: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add syslog-receiver/
git add docker-compose.yml
git commit -m "feat(syslog): add syslog receiver service — UDP/TCP 514, RFC 3164/5424, injects to Redis stream"
```

---

## Task 3: Alert Correlation Engine

**Files:**
- Modify: `server-api/app/models/models.py`
- Modify: `server-api/app/schemas/schemas.py`
- Create: `server-api/app/api/routes/correlation.py`
- Modify: `server-api/app/main.py`
- Modify: `worker/worker/models.py`
- Create: `worker/worker/correlation_engine.py`
- Modify: `worker/worker/alert_manager.py`
- Create: `dashboard/src/pages/CorrelationPage.tsx`
- Modify: `dashboard/src/App.tsx`
- Modify: `dashboard/src/components/Sidebar.tsx`

A correlation rule specifies: match field (e.g. `source_ip`), min count of alerts within a time window, optional severity filter. When those conditions are met, a new alert with title from the rule is created. Redis sorted sets track alert timestamps per field value.

- [ ] **Step 1: Add CorrelationRule model to server-api**

In `server-api/app/models/models.py`, append after the `PlatformSetting` class:

```python
class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title        = Column(String(255), nullable=False)
    description  = Column(Text)
    match_field  = Column(String(100), nullable=False, default="source_ip")  # source_ip | hostname | group_id
    min_count    = Column(Integer, nullable=False, default=5)
    timewindow   = Column(Integer, nullable=False, default=300)  # seconds
    severity_filter = Column(String(20))   # only count alerts with this severity; NULL = any
    output_severity = Column(String(20), nullable=False, default="high")
    output_title = Column(String(255), nullable=False)  # supports {match_value} and {count}
    is_enabled   = Column(Boolean, nullable=False, default=True)
    group_id     = Column(String(100))
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
```

- [ ] **Step 2: Add schemas**

In `server-api/app/schemas/schemas.py`, append a new section at the bottom:

```python
# ─── Correlation Rules ────────────────────────────────────────────

class CorrelationRuleCreate(BaseModel):
    title: str
    description: str | None = None
    match_field: str = "source_ip"
    min_count: int = 5
    timewindow: int = 300
    severity_filter: str | None = None
    output_severity: str = "high"
    output_title: str
    is_enabled: bool = True
    group_id: str | None = None

class CorrelationRuleUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    match_field: str | None = None
    min_count: int | None = None
    timewindow: int | None = None
    severity_filter: str | None = None
    output_severity: str | None = None
    output_title: str | None = None
    is_enabled: bool | None = None
    group_id: str | None = None

class CorrelationRuleOut(BaseModel):
    id: UUID
    title: str
    description: str | None
    match_field: str
    min_count: int
    timewindow: int
    severity_filter: str | None
    output_severity: str
    output_title: str
    is_enabled: bool
    group_id: str | None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}
```

- [ ] **Step 3: Create correlation router**

Create `server-api/app/api/routes/correlation.py`:

```python
# server-api/app/api/routes/correlation.py
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, require_permission
from app.models.models import CorrelationRule, User
from app.schemas.schemas import CorrelationRuleCreate, CorrelationRuleOut, CorrelationRuleUpdate

router = APIRouter(prefix="/api/correlation-rules", tags=["correlation"])
Perm = require_permission("rules:manage")


@router.get("", response_model=list[CorrelationRuleOut])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(CorrelationRule).order_by(CorrelationRule.created_at.desc()))
    return [CorrelationRuleOut.model_validate(r) for r in result.scalars().all()]


@router.post("", response_model=CorrelationRuleOut, status_code=201)
async def create_rule(
    body: CorrelationRuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    rule = CorrelationRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return CorrelationRuleOut.model_validate(rule)


@router.put("/{rule_id}", response_model=CorrelationRuleOut)
async def update_rule(
    rule_id: UUID, body: CorrelationRuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    return CorrelationRuleOut.model_validate(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(Perm)],
):
    result = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Rule not found")
    await db.delete(rule)
    await db.commit()
```

- [ ] **Step 4: Register router and seed default rule in server-api main.py**

In `server-api/app/main.py`, add the import:

```python
from app.api.routes.correlation import router as correlation_router
```

Add `correlation_router` to the `for router in [...]` list.

Add a `_seed_correlation_rules()` function and call it from `lifespan`:

```python
async def _seed_correlation_rules() -> None:
    from sqlalchemy import select
    from app.core.database import AsyncSessionLocal
    from app.models.models import CorrelationRule
    async with AsyncSessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(CorrelationRule))).scalar()
        if count == 0:
            db.add(CorrelationRule(
                title="SSH Brute Force Correlation",
                description="Multiple SSH auth failures from same IP",
                match_field="source_ip",
                min_count=10,
                timewindow=300,
                severity_filter=None,
                output_severity="high",
                output_title="[Correlated] {count} alerts from {match_value} in 5 min",
                is_enabled=True,
            ))
            await db.commit()
```

Add `from sqlalchemy import func` at the top of main.py if not already present, and call `await _seed_correlation_rules()` inside `lifespan` after `_seed_settings()`.

- [ ] **Step 5: Add CorrelationRule model to worker models.py**

In `worker/worker/models.py`, append:

```python
class CorrelationRule(Base):
    __tablename__ = "correlation_rules"
    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    match_field     = Column(String(100), nullable=False, default="source_ip")
    min_count       = Column(Integer, nullable=False, default=5)
    timewindow      = Column(Integer, nullable=False, default=300)
    severity_filter = Column(String(20))
    output_severity = Column(String(20), nullable=False, default="high")
    output_title    = Column(String(255), nullable=False)
    is_enabled      = Column(Boolean, nullable=False, default=True)
    group_id        = Column(String(100))
```

- [ ] **Step 6: Create correlation engine**

Create `worker/worker/correlation_engine.py`:

```python
# worker/worker/correlation_engine.py
"""
Checks correlation rules after every new alert.
Uses Redis sorted sets (ZADD/ZRANGEBYSCORE) for time-windowed counting.
Key format: corr:{rule_id}:{match_value}
"""
import time
import uuid
import structlog
from sqlalchemy import select
from worker.database import AsyncSessionLocal
from worker.models import Alert, CorrelationRule
from worker.redis_client import get_redis

log = structlog.get_logger()

_RULES_TTL = 60.0
_rules_cache: list = []
_rules_loaded_at: float = 0.0


async def _get_rules() -> list:
    global _rules_cache, _rules_loaded_at
    if time.monotonic() - _rules_loaded_at > _RULES_TTL:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(CorrelationRule).where(CorrelationRule.is_enabled == True)
            )
            _rules_cache = result.scalars().all()
            _rules_loaded_at = time.monotonic()
    return _rules_cache


async def check_correlation(
    alert_id: uuid.UUID,
    source_ip: str | None,
    hostname: str | None,
    group_id: str,
    severity: str,
) -> None:
    rules = await _get_rules()
    if not rules:
        return

    redis = await get_redis()
    now = time.time()

    for rule in rules:
        if rule.group_id and rule.group_id != group_id:
            continue
        if rule.severity_filter and rule.severity_filter != severity:
            continue

        match_value = {"source_ip": source_ip, "hostname": hostname, "group_id": group_id}.get(
            rule.match_field
        )
        if not match_value:
            continue

        key = f"corr:{rule.id}:{match_value}"
        window_start = now - rule.timewindow

        await redis.zadd(key, {str(alert_id): now})
        await redis.zremrangebyscore(key, "-inf", window_start)
        await redis.expire(key, rule.timewindow * 2)

        count = await redis.zcard(key)
        if count >= rule.min_count:
            # Prevent duplicate correlated alerts: check a dedup key
            dedup_key = f"corr_fired:{rule.id}:{match_value}"
            if await redis.exists(dedup_key):
                continue
            await redis.setex(dedup_key, rule.timewindow, "1")

            title = rule.output_title.replace("{count}", str(count)).replace("{match_value}", match_value)
            log.info("correlation_triggered", rule_id=str(rule.id), match_value=match_value, count=count)

            async with AsyncSessionLocal() as db:
                corr_alert = Alert(
                    title=title,
                    severity=rule.output_severity,
                    status="new",
                    group_id=group_id,
                    source_ip=source_ip if rule.match_field == "source_ip" else None,
                    hostname=hostname if rule.match_field == "hostname" else None,
                )
                db.add(corr_alert)
                await db.commit()
```

- [ ] **Step 7: Hook correlation check into alert_manager.py**

In `worker/worker/alert_manager.py`, add the import at the top:

```python
from worker.correlation_engine import check_correlation
```

At the end of `create_alert()`, before the `return alert_id` line, add:

```python
    # Fire correlation check (non-blocking, best-effort)
    try:
        await check_correlation(
            alert_id=alert_id,
            source_ip=source_ip,
            hostname=hostname,
            group_id=group_id,
            severity=rule_match["level"],
        )
    except Exception as exc:
        log.error("correlation_check_failed", error=str(exc))

    return alert_id
```

- [ ] **Step 8: Create CorrelationPage.tsx**

Create `dashboard/src/pages/CorrelationPage.tsx`:

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { format } from 'date-fns'
import { Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

interface CorrelationRule {
  id: string
  title: string
  description: string | null
  match_field: string
  min_count: number
  timewindow: number
  severity_filter: string | null
  output_severity: string
  output_title: string
  is_enabled: boolean
  group_id: string | null
  created_at: string
}

const EMPTY: Partial<CorrelationRule> = {
  title: '', match_field: 'source_ip', min_count: 5, timewindow: 300,
  severity_filter: '', output_severity: 'high', output_title: '[Correlated] {count} alerts from {match_value}',
  is_enabled: true,
}

export default function CorrelationPage() {
  const qc = useQueryClient()
  const { hasRole } = useAuthStore()
  const isAdmin = hasRole('admin')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<Partial<CorrelationRule>>(EMPTY)

  const { data: rules = [], isLoading } = useQuery<CorrelationRule[]>({
    queryKey: ['correlation-rules'],
    queryFn: () => api.get('/api/correlation-rules').then(r => r.data),
  })

  const create = useMutation({
    mutationFn: (body: Partial<CorrelationRule>) => api.post('/api/correlation-rules', {
      ...body,
      severity_filter: body.severity_filter || null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['correlation-rules'] }); setShowForm(false); setForm(EMPTY) },
  })

  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/correlation-rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  const toggle = useMutation({
    mutationFn: ({ id, is_enabled }: { id: string; is_enabled: boolean }) =>
      api.put(`/api/correlation-rules/${id}`, { is_enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Correlation Rules</h1>
        {isAdmin && (
          <button onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded text-sm hover:opacity-90">
            <Plus size={14} /> New Rule
          </button>
        )}
      </div>

      {showForm && (
        <div className="mb-6 p-4 border border-border rounded bg-card space-y-3">
          <h2 className="font-semibold text-sm">New Correlation Rule</h2>
          <div className="grid grid-cols-2 gap-3">
            <input placeholder="Rule title" value={form.title || ''} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="col-span-2 px-3 py-2 rounded border border-border bg-background text-sm" />
            <select value={form.match_field} onChange={e => setForm(f => ({ ...f, match_field: e.target.value }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm">
              <option value="source_ip">source_ip</option>
              <option value="hostname">hostname</option>
              <option value="group_id">group_id</option>
            </select>
            <input type="number" placeholder="Min count" value={form.min_count || 5}
              onChange={e => setForm(f => ({ ...f, min_count: Number(e.target.value) }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm" />
            <input type="number" placeholder="Time window (seconds)" value={form.timewindow || 300}
              onChange={e => setForm(f => ({ ...f, timewindow: Number(e.target.value) }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm" />
            <select value={form.output_severity} onChange={e => setForm(f => ({ ...f, output_severity: e.target.value }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm">
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
            </select>
            <input placeholder="Output title (use {count} and {match_value})" value={form.output_title || ''}
              onChange={e => setForm(f => ({ ...f, output_title: e.target.value }))}
              className="col-span-2 px-3 py-2 rounded border border-border bg-background text-sm" />
          </div>
          <div className="flex gap-2">
            <button onClick={() => create.mutate(form)} disabled={create.isPending}
              className="px-4 py-1.5 bg-primary text-primary-foreground rounded text-sm hover:opacity-90 disabled:opacity-50">
              {create.isPending ? 'Saving…' : 'Save'}
            </button>
            <button onClick={() => setShowForm(false)}
              className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted">Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? (
        <p className="text-muted-foreground text-sm">Loading…</p>
      ) : (
        <div className="space-y-2">
          {rules.map(r => (
            <div key={r.id} className="flex items-start justify-between p-4 rounded border border-border bg-card">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm">{r.title}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded ${r.is_enabled ? 'bg-green-500/20 text-green-400' : 'bg-muted text-muted-foreground'}`}>
                    {r.is_enabled ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {r.min_count}+ alerts on <code className="bg-muted px-1 rounded">{r.match_field}</code> within {r.timewindow}s → <span className="font-medium">{r.output_severity}</span>
                </p>
                <p className="text-xs text-muted-foreground">{r.output_title}</p>
              </div>
              {isAdmin && (
                <div className="flex gap-2 ml-4 flex-shrink-0">
                  <button onClick={() => toggle.mutate({ id: r.id, is_enabled: !r.is_enabled })}
                    className="text-xs px-2 py-1 rounded border border-border hover:bg-muted">
                    {r.is_enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button onClick={() => del.mutate(r.id)}
                    className="text-xs px-2 py-1 rounded border border-destructive text-destructive hover:bg-destructive/10">
                    <Trash2 size={12} />
                  </button>
                </div>
              )}
            </div>
          ))}
          {rules.length === 0 && <p className="text-muted-foreground text-sm">No correlation rules defined.</p>}
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 9: Add route and sidebar nav**

In `dashboard/src/App.tsx`, add the import:

```tsx
import CorrelationPage from '@/pages/CorrelationPage'
```

Add the route inside the `<Layout />` route group:

```tsx
<Route path="/correlation" element={<CorrelationPage />} />
```

In `dashboard/src/components/Sidebar.tsx`, add to the imports:

```tsx
import { ..., GitMerge } from 'lucide-react'
```

Add to the `nav` array (after Rules):

```tsx
{ to: '/correlation', label: 'Correlation', icon: GitMerge, minRole: 'viewer' },
```

- [ ] **Step 10: Verify TypeScript builds**

```bash
cd /home/wonka/Documents/hackathon/dashboard
npm run build 2>&1 | tail -10
```

Expected: `✓ built in` with no TypeScript errors.

- [ ] **Step 11: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add server-api/app/models/models.py server-api/app/schemas/schemas.py
git add server-api/app/api/routes/correlation.py server-api/app/main.py
git add worker/worker/models.py worker/worker/correlation_engine.py worker/worker/alert_manager.py
git add dashboard/src/pages/CorrelationPage.tsx dashboard/src/App.tsx dashboard/src/components/Sidebar.tsx
git commit -m "feat(correlation): add alert correlation engine — Redis time-window counting, CRUD API, UI page"
```

---

## Task 4: Email Notifications via SMTP

**Files:**
- Modify: `worker/requirements.txt`
- Create: `worker/worker/email_sender.py`
- Modify: `worker/worker/alert_manager.py`
- Modify: `server-api/app/main.py`

- [ ] **Step 1: Add aiosmtplib to worker dependencies**

In `worker/requirements.txt`, append:

```
aiosmtplib==3.0.2
```

- [ ] **Step 2: Create email_sender.py**

Create `worker/worker/email_sender.py`:

```python
# worker/worker/email_sender.py
"""
Sends HTML email alerts via SMTP.
Reads SMTP config from platform_settings (cached 60s).
Silently skips if smtp_enabled != "true" or smtp_host is empty.
"""
import ssl
import structlog
from datetime import datetime, timezone
from worker.settings_cache import get_setting

log = structlog.get_logger()

_SEVERITY_COLORS = {
    "critical": "#E74C3C",
    "high":     "#E67E22",
    "medium":   "#F39C12",
    "low":      "#3498DB",
    "info":     "#95A5A6",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:20px">
  <div style="max-width:600px;margin:0 auto">
    <h2 style="color:{color};margin-bottom:4px">⚠ SIEM Alert: {title}</h2>
    <p style="color:#94a3b8;font-size:13px;margin:0">{timestamp}</p>
    <table style="width:100%;margin-top:16px;border-collapse:collapse">
      <tr><td style="padding:8px;border:1px solid #1e293b;color:#94a3b8;width:140px">Severity</td>
          <td style="padding:8px;border:1px solid #1e293b;color:{color};font-weight:bold">{severity}</td></tr>
      <tr><td style="padding:8px;border:1px solid #1e293b;color:#94a3b8">Source IP</td>
          <td style="padding:8px;border:1px solid #1e293b">{source_ip}</td></tr>
      <tr><td style="padding:8px;border:1px solid #1e293b;color:#94a3b8">Hostname</td>
          <td style="padding:8px;border:1px solid #1e293b">{hostname}</td></tr>
    </table>
  </div>
</body>
</html>
"""


async def send_alert_email(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
) -> None:
    enabled = await get_setting("smtp_enabled", "false")
    if enabled.lower() != "true":
        return

    smtp_host = await get_setting("smtp_host", "")
    if not smtp_host:
        return

    import aiosmtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    smtp_port = int(await get_setting("smtp_port", "587"))
    smtp_user = await get_setting("smtp_user", "")
    smtp_pass = await get_setting("smtp_password", "")
    smtp_from = await get_setting("smtp_from", smtp_user)
    smtp_to_raw = await get_setting("smtp_to", "")
    min_severity = await get_setting("smtp_min_severity", "high")

    _severity_order = ["info", "low", "medium", "high", "critical"]
    if _severity_order.index(severity) < _severity_order.index(min_severity):
        return

    recipients = [r.strip() for r in smtp_to_raw.split(",") if r.strip()]
    if not recipients:
        return

    color = _SEVERITY_COLORS.get(severity, "#95A5A6")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html = _HTML_TEMPLATE.format(
        title=title, severity=severity.upper(), color=color,
        source_ip=source_ip or "—", hostname=hostname or "—", timestamp=ts,
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[SIEM] {severity.upper()}: {title}"
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        use_tls = smtp_port == 465
        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=smtp_port,
            start_tls=(not use_tls and smtp_port == 587),
            use_tls=use_tls,
            username=smtp_user or None,
            password=smtp_pass or None,
            timeout=15,
        )
        log.info("email_sent", title=title, severity=severity, recipients=len(recipients))
    except Exception as exc:
        log.warning("email_send_failed", error=str(exc))
```

- [ ] **Step 3: Hook email into alert_manager.py**

In `worker/worker/alert_manager.py`, add import at the top:

```python
from worker.email_sender import send_alert_email
```

In `create_alert()`, add the email call after the AI queue push block (before `return alert_id`):

```python
    try:
        await send_alert_email(
            title=rule_match["title"],
            severity=rule_match["level"],
            source_ip=source_ip,
            hostname=hostname,
        )
    except Exception as exc:
        log.error("email_dispatch_failed", error=str(exc))

    return alert_id
```

- [ ] **Step 4: Seed SMTP settings in server-api/app/main.py**

In the `_DEFAULT_SETTINGS` list in `server-api/app/main.py`, append:

```python
    ("smtp_enabled",      "false",     False, "Enable email alert notifications (true/false)"),
    ("smtp_host",         "",          False, "SMTP server hostname (e.g. smtp.gmail.com)"),
    ("smtp_port",         "587",       False, "SMTP port (587=STARTTLS, 465=SSL, 25=plain)"),
    ("smtp_user",         "",          False, "SMTP username / login email"),
    ("smtp_password",     "",          True,  "SMTP password or app password"),
    ("smtp_from",         "",          False, "From address (defaults to smtp_user if empty)"),
    ("smtp_to",           "",          False, "Comma-separated recipient email addresses"),
    ("smtp_min_severity", "high",      False, "Minimum severity to email (info/low/medium/high/critical)"),
```

- [ ] **Step 5: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add worker/requirements.txt worker/worker/email_sender.py worker/worker/alert_manager.py
git add server-api/app/main.py
git commit -m "feat(email): add SMTP email notifications for alerts — configurable via Settings page"
```

---

## Task 5: Audit Log UI

**Files:**
- Modify: `server-api/app/schemas/schemas.py`
- Create: `server-api/app/api/routes/audit_logs.py`
- Modify: `server-api/app/main.py`
- Create: `dashboard/src/pages/AuditLogsPage.tsx`
- Modify: `dashboard/src/App.tsx`
- Modify: `dashboard/src/components/Sidebar.tsx`

The `AuditLog` model and `audit_log()` service already exist. This task adds the GET route and UI page.

- [ ] **Step 1: Add AuditLogOut schema**

In `server-api/app/schemas/schemas.py`, append:

```python
# ─── Audit Logs ──────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: UUID
    actor_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    detail: dict[str, Any]
    created_at: datetime
    model_config = {"from_attributes": True}
```

- [ ] **Step 2: Create audit_logs route**

Create `server-api/app/api/routes/audit_logs.py`:

```python
# server-api/app/api/routes/audit_logs.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_permission
from app.models.models import AuditLog
from app.schemas.schemas import AuditLogOut, PaginatedResponse

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])
Perm = require_permission("settings:manage")  # admin-only


@router.get("", response_model=PaginatedResponse)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _=Depends(Perm),
    page: int = 1,
    page_size: int = 50,
    action: str | None = None,
    resource_type: str | None = None,
):
    q = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        q = q.where(AuditLog.action == action)
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    result = await db.execute(q.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[AuditLogOut.model_validate(r) for r in result.scalars().all()],
    )
```

- [ ] **Step 3: Register route in main.py**

In `server-api/app/main.py`, add:

```python
from app.api.routes.audit_logs import router as audit_logs_router
```

Add `audit_logs_router` to the `for router in [...]` list.

- [ ] **Step 4: Create AuditLogsPage.tsx**

Create `dashboard/src/pages/AuditLogsPage.tsx`:

```tsx
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { format } from 'date-fns'

interface AuditLog {
  id: string
  actor_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  detail: Record<string, unknown>
  created_at: string
}

interface Paginated { total: number; page: number; page_size: number; items: AuditLog[] }

export default function AuditLogsPage() {
  const [page, setPage] = useState(1)
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')

  const { data, isLoading } = useQuery<Paginated>({
    queryKey: ['audit-logs', page, actionFilter, resourceFilter],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), page_size: '50' })
      if (actionFilter) params.set('action', actionFilter)
      if (resourceFilter) params.set('resource_type', resourceFilter)
      return api.get(`/api/audit-logs?${params}`).then(r => r.data)
    },
  })

  const totalPages = data ? Math.ceil(data.total / data.page_size) : 1

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Audit Log</h1>
        <span className="text-sm text-muted-foreground">{data?.total ?? 0} entries</span>
      </div>

      <div className="flex gap-3 mb-4">
        <input placeholder="Filter by action…" value={actionFilter}
          onChange={e => { setActionFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm w-52" />
        <input placeholder="Filter by resource type…" value={resourceFilter}
          onChange={e => { setResourceFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm w-52" />
      </div>

      {isLoading ? (
        <p className="text-muted-foreground text-sm">Loading…</p>
      ) : (
        <div className="rounded border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted text-muted-foreground text-xs uppercase">
              <tr>
                <th className="px-4 py-2 text-left">Time</th>
                <th className="px-4 py-2 text-left">Action</th>
                <th className="px-4 py-2 text-left">Resource</th>
                <th className="px-4 py-2 text-left">Resource ID</th>
                <th className="px-4 py-2 text-left">Detail</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map(log => (
                <tr key={log.id} className="border-t border-border hover:bg-muted/30">
                  <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">
                    {format(new Date(log.created_at), 'yyyy-MM-dd HH:mm:ss')}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">{log.action}</td>
                  <td className="px-4 py-2 text-muted-foreground">{log.resource_type ?? '—'}</td>
                  <td className="px-4 py-2 text-muted-foreground font-mono text-xs truncate max-w-[120px]">
                    {log.resource_id ? log.resource_id.slice(0, 8) + '…' : '—'}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground text-xs truncate max-w-[200px]">
                    {Object.keys(log.detail).length > 0 ? JSON.stringify(log.detail) : '—'}
                  </td>
                </tr>
              ))}
              {(data?.items ?? []).length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">No audit log entries.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-4">
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            className="px-3 py-1 rounded border border-border text-sm disabled:opacity-40 hover:bg-muted">Prev</button>
          <span className="px-3 py-1 text-sm text-muted-foreground">{page} / {totalPages}</span>
          <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
            className="px-3 py-1 rounded border border-border text-sm disabled:opacity-40 hover:bg-muted">Next</button>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 5: Add route and sidebar item**

In `dashboard/src/App.tsx`, add:

```tsx
import AuditLogsPage from '@/pages/AuditLogsPage'
```

Add route (admin-only):

```tsx
<Route path="/audit-logs" element={<ProtectedRoute minRole="admin"><AuditLogsPage /></ProtectedRoute>} />
```

In `dashboard/src/components/Sidebar.tsx`, add to imports:

```tsx
import { ..., ClipboardList } from 'lucide-react'
```

Add to `nav` array (after Webhooks):

```tsx
{ to: '/audit-logs', label: 'Audit Log', icon: ClipboardList, minRole: 'admin' },
```

- [ ] **Step 6: Verify TypeScript build**

```bash
cd /home/wonka/Documents/hackathon/dashboard
npm run build 2>&1 | tail -5
```

Expected: `✓ built in`

- [ ] **Step 7: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add server-api/app/schemas/schemas.py server-api/app/api/routes/audit_logs.py server-api/app/main.py
git add dashboard/src/pages/AuditLogsPage.tsx dashboard/src/App.tsx dashboard/src/components/Sidebar.tsx
git commit -m "feat(audit): add audit log API endpoint and dashboard UI page (admin only)"
```

---

## Task 6: Report Export (CSV + PDF)

**Files:**
- Modify: `server-api/requirements.txt`
- Create: `server-api/app/api/routes/export.py`
- Modify: `server-api/app/main.py`
- Modify: `dashboard/src/pages/AlertsPage.tsx`
- Modify: `dashboard/src/pages/CasesPage.tsx`

CSV uses Python's built-in `csv` module via `StreamingResponse`. PDF uses `reportlab` with a simple table layout.

- [ ] **Step 1: Add reportlab to server-api requirements**

Check `server-api/requirements.txt` path:

```bash
ls /home/wonka/Documents/hackathon/server-api/requirements.txt 2>/dev/null || ls /home/wonka/Documents/hackathon/server-api/pyproject.toml
```

Add `reportlab==4.2.5` to whichever file manages server-api dependencies.

- [ ] **Step 2: Create export router**

Create `server-api/app/api/routes/export.py`:

```python
# server-api/app/api/routes/export.py
import csv
import io
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, Case, User

router = APIRouter(prefix="/api/export", tags=["export"])

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Alerts CSV ───────────────────────────────────────────────────

@router.get("/alerts/csv")
async def export_alerts_csv(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=1000, le=5000),
):
    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    result = await db.execute(q)
    alerts = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "source_ip", "hostname", "group_id", "created_at"])
    for a in alerts:
        writer.writerow([
            str(a.id), a.title, a.severity, a.status,
            a.source_ip or "", a.hostname or "", a.group_id,
            a.created_at.isoformat() if a.created_at else "",
        ])
    output.seek(0)
    filename = f"alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.read()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Alerts PDF ───────────────────────────────────────────────────

@router.get("/alerts/pdf")
async def export_alerts_pdf(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=200, le=1000),
):
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm

    q = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    result = await db.execute(q)
    alerts = result.scalars().all()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=1*cm, rightMargin=1*cm,
                             topMargin=1.5*cm, bottomMargin=1*cm)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SIEM Platform — Alerts Report", styles["Title"]))
    elements.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  Total: {len(alerts)}",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 0.5*cm))

    _SEV_COLORS = {
        "critical": colors.HexColor("#E74C3C"),
        "high":     colors.HexColor("#E67E22"),
        "medium":   colors.HexColor("#F1C40F"),
        "low":      colors.HexColor("#3498DB"),
        "info":     colors.HexColor("#95A5A6"),
    }

    table_data = [["Severity", "Title", "Status", "Source IP", "Hostname", "Time"]]
    for a in alerts:
        ts = a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else ""
        table_data.append([
            a.severity.upper(),
            (a.title[:60] + "…") if len(a.title) > 60 else a.title,
            a.status, a.source_ip or "—", a.hostname or "—", ts,
        ])

    col_widths = [2.5*cm, 9*cm, 2.5*cm, 3.5*cm, 3.5*cm, 4*cm]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",    (0, 0), (-1, 0), 8),
        ("FONTSIZE",    (0, 1), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f1117"), colors.HexColor("#151c28")]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#1e293b")),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])
    # Color severity column per row
    for i, a in enumerate(alerts, start=1):
        c = _SEV_COLORS.get(a.severity, colors.gray)
        style.add("TEXTCOLOR", (0, i), (0, i), c)
    table.setStyle(style)
    elements.append(table)

    doc.build(elements)
    buf.seek(0)
    filename = f"alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        iter([buf.read()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Cases CSV ────────────────────────────────────────────────────

@router.get("/cases/csv")
async def export_cases_csv(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    limit: int = Query(default=1000, le=5000),
):
    q = select(Case).order_by(Case.created_at.desc()).limit(limit)
    if group_filter:
        q = q.where(Case.group_id == group_filter)
    result = await db.execute(q)
    cases = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "severity", "status", "created_by_ai", "group_id", "created_at"])
    for c in cases:
        writer.writerow([
            str(c.id), c.title, c.severity, c.status,
            str(c.created_by_ai), c.group_id,
            c.created_at.isoformat() if c.created_at else "",
        ])
    output.seek(0)
    filename = f"cases_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.read()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

- [ ] **Step 3: Register export router in main.py**

In `server-api/app/main.py`, add:

```python
from app.api.routes.export import router as export_router
```

Add `export_router` to the `for router in [...]` list.

- [ ] **Step 4: Add Export button to AlertsPage.tsx**

In `dashboard/src/pages/AlertsPage.tsx`, add the export button to the header div. Import `Download` from lucide-react and add these buttons next to the status filter:

```tsx
import { Crosshair, Download } from 'lucide-react'

// Inside the component, in the header div alongside the existing filter select:
<div className="flex items-center gap-2">
  <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
    className="px-3 py-1.5 rounded border border-border bg-background text-sm">
    <option value="">All statuses</option>
    <option value="new">New</option>
    <option value="acknowledged">Acknowledged</option>
    <option value="resolved">Resolved</option>
  </select>
  <a href="/api/export/alerts/csv" download
    className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
    <Download size={13} /> CSV
  </a>
  <a href="/api/export/alerts/pdf" download
    className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
    <Download size={13} /> PDF
  </a>
</div>
```

> Note: The `<a href>` approach works because the export endpoint doesn't require a Bearer token check beyond what the cookie/proxy provides. If your setup uses Authorization header auth (no cookies), replace the `<a>` tags with a button that does `api.get(url, { responseType: 'blob' })` and triggers a download via `URL.createObjectURL`.

- [ ] **Step 5: Add Export button to CasesPage.tsx**

In `dashboard/src/pages/CasesPage.tsx`, apply the same pattern — read the current header section and add a CSV download link next to any existing controls.

Import `Download` and add:

```tsx
<a href="/api/export/cases/csv" download
  className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
  <Download size={13} /> CSV
</a>
```

- [ ] **Step 6: Verify TypeScript build**

```bash
cd /home/wonka/Documents/hackathon/dashboard
npm run build 2>&1 | tail -5
```

Expected: `✓ built in`

- [ ] **Step 7: Commit**

```bash
cd /home/wonka/Documents/hackathon
git add server-api/app/api/routes/export.py server-api/app/main.py
git add dashboard/src/pages/AlertsPage.tsx dashboard/src/pages/CasesPage.tsx
git commit -m "feat(export): add CSV and PDF report export for alerts and cases"
```

---

## Self-Review

**Spec coverage check:**
1. ✅ Windows agent — build tags (isolation_linux/windows), cross-compile, PS1 installer, Makefile
2. ✅ Syslog receiver — UDP+TCP, RFC 3164+5424, Redis injection, Docker service
3. ✅ Alert correlation — DB model, worker engine, Redis time-windows, API CRUD, UI page
4. ✅ Email notifications — aiosmtplib, HTML template, SMTP settings seeded, severity filter
5. ✅ Audit log UI — server route with pagination/filter, React table, admin-only nav
6. ✅ Report export — CSV (all pages, StreamingResponse), PDF (reportlab with styled table), download buttons

**Placeholder scan:** No TBD/TODO found.

**Type consistency:**
- `CorrelationRule` model in server-api and worker use identical field names
- `CorrelationRuleOut` schema matches model fields exactly
- `AuditLogOut` fields match existing `AuditLog` model columns
- Export routes import `Alert`/`Case` models from `app.models.models` — both already exist
