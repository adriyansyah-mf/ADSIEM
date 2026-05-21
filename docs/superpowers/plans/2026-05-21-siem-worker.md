# SIEM Platform — Plan 2: Worker Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Python async worker that consumes Redis Streams, decodes logs, runs Sigma rule matching, generates alerts, seeds sample decoders/rules, and retries webhook deliveries.

**Architecture:** Single asyncio process with three concurrent tasks: main consumer loop (XREADGROUP), background rule/decoder reload (every 60s), and webhook retry loop (every 30s). Exposes /health and /metrics on port 8001.

**Tech Stack:** Python 3.12, asyncio, redis-py (asyncio), asyncpg, SQLAlchemy 2.x async, PyYAML, structlog, prometheus-client, httpx

**Prerequisite:** Plan 1 must be complete. Database schema and server-api must be running.

---

## File Map

```
worker/
├── Dockerfile
├── requirements.txt
├── worker/
│   ├── __init__.py
│   ├── main.py              — entry point: wires all tasks, health server
│   ├── config.py            — settings from env
│   ├── database.py          — async SQLAlchemy session
│   ├── redis_client.py      — Redis connection
│   ├── consumer.py          — XREADGROUP loop, message dispatch
│   ├── decoder_engine.py    — regex decoder: parse raw log → normalized fields
│   ├── sigma_engine.py      — Sigma condition evaluation + threshold + suppression
│   ├── alert_manager.py     — save alerts, enqueue webhook deliveries
│   ├── webhook_sender.py    — retry loop: deliver pending webhook_deliveries
│   └── seeder.py            — seed decoders/rules from YAML files on first start

decoders/
├── linux_auth_failed.yaml
├── linux_sudo.yaml
├── nginx_access.yaml
└── generic_syslog.yaml

rules/
├── ssh_failed_login.yaml
├── ssh_brute_force.yaml
├── sudo_executed.yaml
├── nginx_suspicious_path.yaml
├── access_env_file.yaml
├── access_etc_passwd.yaml
└── wordpress_admin_probe.yaml

tests/worker/
├── conftest.py
├── test_decoder_engine.py
└── test_sigma_engine.py
```

---

## Task 1: Worker Scaffold

**Files:**
- Create: `worker/requirements.txt`
- Create: `worker/Dockerfile`
- Create: `worker/worker/__init__.py`
- Create: `worker/worker/config.py`
- Create: `worker/worker/database.py`
- Create: `worker/worker/redis_client.py`

- [ ] **Step 1: Write requirements.txt**

```txt
sqlalchemy[asyncio]==2.0.36
asyncpg==0.30.0
redis==5.2.0
pyyaml==6.0.2
structlog==24.4.0
prometheus-client==0.21.1
httpx==0.28.0
```

- [ ] **Step 2: Write Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker/ ./worker/

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"

CMD ["python", "-m", "worker.main"]
```

- [ ] **Step 3: Write config.py**

```python
# worker/worker/config.py
import os

DATABASE_URL: str = os.environ.get("DATABASE_URL", "postgresql+asyncpg://soc:soc@postgres:5432/soc_platform")
REDIS_URL: str = os.environ.get("REDIS_URL", "redis://redis:6379/0")
REDIS_STREAM_KEY: str = os.environ.get("REDIS_STREAM_KEY", "siem:logs")
REDIS_CONSUMER_GROUP: str = os.environ.get("REDIS_CONSUMER_GROUP", "siem-workers")
DECODERS_DIR: str = os.environ.get("DECODERS_DIR", "/app/decoders")
RULES_DIR: str = os.environ.get("RULES_DIR", "/app/rules")
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "info")
RELOAD_INTERVAL: int = int(os.environ.get("RELOAD_INTERVAL", "60"))
WEBHOOK_RETRY_INTERVAL: int = int(os.environ.get("WEBHOOK_RETRY_INTERVAL", "30"))
MAX_WEBHOOK_ATTEMPTS: int = int(os.environ.get("MAX_WEBHOOK_ATTEMPTS", "5"))
```

- [ ] **Step 4: Write database.py**

```python
# worker/worker/database.py
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from worker.config import DATABASE_URL

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
```

- [ ] **Step 5: Write redis_client.py**

```python
# worker/worker/redis_client.py
import redis.asyncio as aioredis
from worker.config import REDIS_URL

_redis: aioredis.Redis | None = None

async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis
```

- [ ] **Step 6: Commit**

```bash
git add worker/ && git commit -m "feat: scaffold worker project structure"
```

---

## Task 2: Decoder Engine

**Files:**
- Create: `worker/worker/decoder_engine.py`
- Create: `tests/worker/test_decoder_engine.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/worker/test_decoder_engine.py
import pytest
from worker.decoder_engine import DecoderEngine

DECODER_YAML_AUTH = """
name: linux_auth_failed
log_type: linux_auth
type: regex
priority: 10
enabled: true
pattern: 'Failed password for (?P<user>\\S+) from (?P<src_ip>\\S+) port (?P<port>\\d+)'
fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip
  user.name: user
  source.port: port
"""

DECODER_YAML_SUDO = """
name: linux_sudo
log_type: linux_auth
type: regex
priority: 20
enabled: true
pattern: '(?P<user>\\S+) : TTY=(?P<tty>\\S+) ; PWD=(?P<pwd>\\S+) ; USER=(?P<run_as>\\S+) ; COMMAND=(?P<cmd>.+)'
fields:
  event.category: process
  event.action: sudo_command
  user.name: user
  process.command_line: cmd
"""

def test_decode_ssh_failed_password():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "May 21 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    result = engine.decode("linux_auth", raw)
    assert result["event.action"] == "login_failed"
    assert result["source.ip"] == "1.2.3.4"
    assert result["user.name"] == "root"

def test_no_match_returns_empty():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "Accepted publickey for admin from 10.0.0.1 port 22"
    result = engine.decode("linux_auth", raw)
    assert result == {}

def test_wrong_log_type_skipped():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "Failed password for root from 1.2.3.4 port 22 ssh2"
    result = engine.decode("nginx_access", raw)
    assert result == {}

def test_priority_order_first_match_wins():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_SUDO, DECODER_YAML_AUTH])
    raw = "May 21 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    result = engine.decode("linux_auth", raw)
    assert result["event.action"] == "login_failed"

def test_static_field_applied():
    engine = DecoderEngine()
    engine.load_from_yaml_list([DECODER_YAML_AUTH])
    raw = "May 21 sshd: Failed password for alice from 10.0.0.1 port 22 ssh2"
    result = engine.decode("linux_auth", raw)
    assert result["event.category"] == "authentication"
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
cd worker && pip install -r requirements.txt -q
python -m pytest ../tests/worker/test_decoder_engine.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'worker.decoder_engine'`

- [ ] **Step 3: Write decoder_engine.py**

```python
# worker/worker/decoder_engine.py
import re
import yaml
from dataclasses import dataclass, field
from typing import Any

@dataclass
class DecoderDef:
    name: str
    log_type: str
    pattern: re.Pattern
    fields_map: dict[str, str]
    static_fields: dict[str, str]
    priority: int

class DecoderEngine:
    def __init__(self):
        self._decoders: list[DecoderDef] = []

    def load_from_yaml_list(self, yaml_contents: list[str]) -> None:
        decoders = []
        for content in yaml_contents:
            try:
                d = yaml.safe_load(content)
                if not d.get("enabled", True):
                    continue
                fields_map = {}
                static_fields = {}
                for output_field, source in d.get("fields", {}).items():
                    pattern_obj = re.compile(d["pattern"])
                    if source in pattern_obj.groupindex:
                        fields_map[output_field] = source
                    else:
                        static_fields[output_field] = source
                decoders.append(DecoderDef(
                    name=d["name"],
                    log_type=d["log_type"],
                    pattern=re.compile(d["pattern"]),
                    fields_map=fields_map,
                    static_fields=static_fields,
                    priority=d.get("priority", 100),
                ))
            except Exception:
                continue
        self._decoders = sorted(decoders, key=lambda x: x.priority)

    def decode(self, log_type: str, raw_message: str) -> dict[str, Any]:
        for decoder in self._decoders:
            if decoder.log_type != log_type:
                continue
            match = re.search(decoder.pattern, raw_message)
            if not match:
                continue
            groups = match.groupdict()
            result: dict[str, Any] = {}
            for output_field, group_name in decoder.fields_map.items():
                result[output_field] = groups.get(group_name)
            result.update(decoder.static_fields)
            return result
        return {}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
python -m pytest ../tests/worker/test_decoder_engine.py -v
```

Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/worker/decoder_engine.py tests/worker/test_decoder_engine.py
git commit -m "feat: add decoder engine with regex matching and field mapping"
```

---

## Task 3: Sigma Engine

**Files:**
- Create: `worker/worker/sigma_engine.py`
- Create: `tests/worker/test_sigma_engine.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/worker/test_sigma_engine.py
import pytest
from worker.sigma_engine import SigmaEngine

RULE_SSH_FAILED = """
title: SSH Failed Login
id: rule-ssh-failed
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
"""

RULE_BRUTE_FORCE = """
title: SSH Brute Force
id: rule-ssh-brute
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
threshold:
  count: 3
  timewindow: 300
  group_by: source.ip
suppression:
  timewindow: 600
level: high
"""

RULE_NGINX_ENV = """
title: Access to .env file
id: rule-nginx-env
logsource:
  product: nginx
detection:
  selection:
    request|contains: ".env"
  condition: selection
level: high
"""

RULE_COMPOUND = """
title: Compound Rule
id: rule-compound
logsource:
  product: linux
detection:
  selection_a:
    event.action: login_failed
  selection_b:
    source.ip|startswith: "10."
  condition: selection_a and selection_b
level: medium
"""

@pytest.fixture
def engine():
    e = SigmaEngine()
    e.load_from_yaml_list([RULE_SSH_FAILED, RULE_NGINX_ENV, RULE_COMPOUND])
    return e

def test_exact_match(engine):
    event = {"event.action": "login_failed"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "SSH Failed Login" in titles

def test_no_match(engine):
    event = {"event.action": "login_success"}
    matches = engine.evaluate(event)
    assert not any(m["title"] == "SSH Failed Login" for m in matches)

def test_contains_modifier(engine):
    event = {"request": "GET /.env HTTP/1.1"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Access to .env file" in titles

def test_compound_and_condition(engine):
    event = {"event.action": "login_failed", "source.ip": "10.0.0.1"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Compound Rule" in titles

def test_compound_and_fails_when_one_part_missing(engine):
    event = {"event.action": "login_failed", "source.ip": "8.8.8.8"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Compound Rule" not in titles

def test_startswith_modifier(engine):
    event = {"source.ip": "10.5.6.7", "event.action": "login_failed"}
    matches = engine.evaluate(event)
    titles = [m["title"] for m in matches]
    assert "Compound Rule" in titles
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
python -m pytest ../tests/worker/test_sigma_engine.py -v 2>&1 | head -10
```

Expected: `ModuleNotFoundError: No module named 'worker.sigma_engine'`

- [ ] **Step 3: Write sigma_engine.py**

```python
# worker/worker/sigma_engine.py
import re
import time
import yaml
from dataclasses import dataclass, field
from typing import Any

@dataclass
class RuleDef:
    id: str
    title: str
    level: str
    logsource: dict
    detection: dict
    tags: list[str]
    mitre_tags: list[str]
    threshold: dict | None
    suppression: dict | None

class SigmaEngine:
    def __init__(self):
        self._rules: list[RuleDef] = []
        self._threshold_hits: dict[str, list[float]] = {}
        self._suppressed: dict[str, float] = {}

    def load_from_yaml_list(self, yaml_contents: list[str]) -> None:
        rules = []
        for content in yaml_contents:
            try:
                d = yaml.safe_load(content)
                rules.append(RuleDef(
                    id=d.get("id", d.get("title", "unknown")),
                    title=d.get("title", "Untitled"),
                    level=d.get("level", "medium"),
                    logsource=d.get("logsource", {}),
                    detection=d.get("detection", {}),
                    tags=d.get("tags", []),
                    mitre_tags=[t for t in d.get("tags", []) if t.startswith("attack.")],
                    threshold=d.get("threshold"),
                    suppression=d.get("suppression"),
                ))
            except Exception:
                continue
        self._rules = rules

    def evaluate(self, event: dict[str, Any]) -> list[dict]:
        now = time.time()
        matches = []
        for rule in self._rules:
            if not self._detection_matches(rule.detection, event):
                continue
            if rule.threshold:
                if not self._check_threshold(rule, event, now):
                    continue
            if rule.suppression:
                suppress_key = self._suppression_key(rule, event)
                if suppress_key in self._suppressed:
                    if now < self._suppressed[suppress_key]:
                        continue
                window = rule.suppression.get("timewindow", 3600)
                self._suppressed[suppress_key] = now + window
            matches.append({
                "id": rule.id,
                "title": rule.title,
                "level": rule.level,
                "tags": rule.tags,
                "mitre_tags": rule.mitre_tags,
            })
        return matches

    def _check_threshold(self, rule: RuleDef, event: dict, now: float) -> bool:
        th = rule.threshold
        count = th.get("count", 1)
        window = th.get("timewindow", 300)
        group_by = th.get("group_by")
        group_val = event.get(group_by, "_all") if group_by else "_all"
        key = f"{rule.id}:{group_val}"

        hits = self._threshold_hits.setdefault(key, [])
        hits.append(now)
        hits[:] = [t for t in hits if now - t <= window]

        return len(hits) >= count

    def _suppression_key(self, rule: RuleDef, event: dict) -> str:
        src_ip = event.get("source.ip", "unknown")
        return f"suppress:{rule.id}:{src_ip}"

    def _detection_matches(self, detection: dict, event: dict) -> bool:
        condition = detection.get("condition", "selection")
        named: dict[str, bool] = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                named[key] = self._evaluate_selection(value, event)
        return self._eval_condition(condition.strip(), named)

    def _evaluate_selection(self, selection: dict, event: dict) -> bool:
        return all(self._match_field(k, v, event) for k, v in selection.items())

    def _match_field(self, field_key: str, condition_value: Any, event: dict) -> bool:
        if "|" in field_key:
            field, modifier = field_key.split("|", 1)
        else:
            field, modifier = field_key, None
        field_value = event.get(field)
        if isinstance(condition_value, list):
            return any(self._apply_modifier(field_value, v, modifier) for v in condition_value)
        return self._apply_modifier(field_value, condition_value, modifier)

    def _apply_modifier(self, field_value: Any, condition_value: Any, modifier: str | None) -> bool:
        if field_value is None:
            return False
        fv = str(field_value)
        cv = str(condition_value)
        if modifier is None:
            return fv == cv
        elif modifier == "contains":
            return cv in fv
        elif modifier == "startswith":
            return fv.startswith(cv)
        elif modifier == "endswith":
            return fv.endswith(cv)
        elif modifier == "re":
            return bool(re.search(cv, fv))
        return fv == cv

    def _eval_condition(self, expr: str, selections: dict[str, bool]) -> bool:
        expr = expr.strip()
        if " or " in expr:
            return any(self._eval_condition(p.strip(), selections) for p in expr.split(" or "))
        if " and " in expr:
            return all(self._eval_condition(p.strip(), selections) for p in expr.split(" and "))
        if expr.startswith("not "):
            return not self._eval_condition(expr[4:].strip(), selections)
        return selections.get(expr, False)
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
python -m pytest ../tests/worker/test_sigma_engine.py -v
```

Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/worker/sigma_engine.py tests/worker/test_sigma_engine.py
git commit -m "feat: add Sigma rule engine with condition eval, threshold, and suppression"
```

---

## Task 4: Alert Manager

**Files:**
- Create: `worker/worker/alert_manager.py`

- [ ] **Step 1: Write alert_manager.py**

```python
# worker/worker/alert_manager.py
import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from worker.database import AsyncSessionLocal

async def create_alert(
    rule_match: dict,
    event_id: uuid.UUID | None,
    agent_id: uuid.UUID | None,
    group_id: str,
    source_ip: str | None,
    hostname: str | None,
) -> uuid.UUID:
    from worker.models import Alert, WebhookConfig, WebhookDelivery
    async with AsyncSessionLocal() as db:
        alert = Alert(
            title=rule_match["title"],
            severity=rule_match["level"],
            status="new",
            rule_id=None,
            event_id=event_id,
            agent_id=agent_id,
            group_id=group_id,
            source_ip=source_ip,
            hostname=hostname,
        )
        db.add(alert)
        await db.flush()

        payload = {
            "alert_id": str(alert.id),
            "title": rule_match["title"],
            "severity": rule_match["level"],
            "source_ip": source_ip,
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        result = await db.execute(
            select(WebhookConfig).where(
                WebhookConfig.is_enabled == True,
                (WebhookConfig.group_id == None) | (WebhookConfig.group_id == group_id)
            )
        )
        webhooks = result.scalars().all()
        for webhook in webhooks:
            db.add(WebhookDelivery(
                alert_id=alert.id,
                webhook_config_id=webhook.id,
                payload=payload,
                status="pending",
                attempts=0,
            ))

        await db.commit()
        return alert.id
```

- [ ] **Step 2: Write worker/models.py (re-use server-api models for DB access)**

```python
# worker/worker/models.py
# Re-export SQLAlchemy models for use in worker.
# These mirror the server-api models exactly — same tables.
import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, ARRAY
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship

class Base(DeclarativeBase):
    pass

def now_utc():
    return datetime.now(timezone.utc)

class Agent(Base):
    __tablename__ = "agents"
    id       = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id = Column(String(100), nullable=False, default="default")
    hostname = Column(String(255), nullable=False)

class RawLog(Base):
    __tablename__ = "raw_logs"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    log_type    = Column(String(100))
    raw_message = Column(Text, nullable=False)
    received_at = Column(DateTime(timezone=True), default=now_utc)

class Event(Base):
    __tablename__ = "events"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    raw_log_id     = Column(UUID(as_uuid=True), ForeignKey("raw_logs.id", ondelete="SET NULL"))
    agent_id       = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id       = Column(String(100), nullable=False, default="default")
    decoded_fields = Column(JSONB, nullable=False, default=dict)
    event_category = Column(String(100))
    event_action   = Column(String(100))
    source_ip      = Column(String(45))
    user_name      = Column(String(255))
    created_at     = Column(DateTime(timezone=True), default=now_utc)

class Rule(Base):
    __tablename__ = "rules"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    content    = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)

class Decoder(Base):
    __tablename__ = "decoders"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    content    = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    priority   = Column(Integer, nullable=False, default=100)

class Alert(Base):
    __tablename__ = "alerts"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title       = Column(String(255), nullable=False)
    severity    = Column(String(20), nullable=False, default="medium")
    status      = Column(String(30), nullable=False, default="new")
    rule_id     = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"))
    event_id    = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"))
    agent_id    = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    group_id    = Column(String(100), nullable=False, default="default")
    source_ip   = Column(String(45))
    hostname    = Column(String(255))
    assignee_id = Column(UUID(as_uuid=True))
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class WebhookConfig(Base):
    __tablename__ = "webhook_configs"
    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name       = Column(String(255), nullable=False)
    url        = Column(Text, nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    group_id   = Column(String(100))

class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id          = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    webhook_config_id = Column(UUID(as_uuid=True), ForeignKey("webhook_configs.id", ondelete="CASCADE"), nullable=False)
    payload           = Column(JSONB, nullable=False, default=dict)
    status            = Column(String(20), nullable=False, default="pending")
    attempts          = Column(Integer, nullable=False, default=0)
    last_attempted_at = Column(DateTime(timezone=True))
    created_at        = Column(DateTime(timezone=True), default=now_utc)
    updated_at        = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
```

- [ ] **Step 3: Commit**

```bash
git add worker/worker/alert_manager.py worker/worker/models.py
git commit -m "feat: add alert manager and worker DB models"
```

---

## Task 5: Webhook Sender

**Files:**
- Create: `worker/worker/webhook_sender.py`

- [ ] **Step 1: Write webhook_sender.py**

```python
# worker/worker/webhook_sender.py
import asyncio
import math
from datetime import datetime, timezone
import httpx
import structlog
from sqlalchemy import select
from worker.config import MAX_WEBHOOK_ATTEMPTS, WEBHOOK_RETRY_INTERVAL
from worker.database import AsyncSessionLocal
from worker.models import WebhookConfig, WebhookDelivery

log = structlog.get_logger()

async def webhook_retry_loop() -> None:
    while True:
        await asyncio.sleep(WEBHOOK_RETRY_INTERVAL)
        try:
            await _process_pending_deliveries()
        except Exception as exc:
            log.error("webhook_retry_error", error=str(exc))

async def _process_pending_deliveries() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(WebhookDelivery, WebhookConfig)
            .join(WebhookConfig, WebhookDelivery.webhook_config_id == WebhookConfig.id)
            .where(
                WebhookDelivery.status.notin_(["delivered", "failed"]),
                WebhookDelivery.attempts < MAX_WEBHOOK_ATTEMPTS,
            )
        )
        rows = result.all()

    for delivery, config in rows:
        next_attempt_time = _backoff_time(delivery.attempts)
        if delivery.last_attempted_at:
            elapsed = (datetime.now(timezone.utc) - delivery.last_attempted_at).total_seconds()
            if elapsed < next_attempt_time:
                continue
        await _deliver(delivery, config)

async def _deliver(delivery: WebhookDelivery, config: WebhookConfig) -> None:
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(config.url, json=delivery.payload)
                resp.raise_for_status()
            status = "delivered"
            log.info("webhook_delivered", delivery_id=str(delivery.id), url=config.url)
        except Exception as exc:
            new_attempts = delivery.attempts + 1
            status = "failed" if new_attempts >= MAX_WEBHOOK_ATTEMPTS else "pending"
            log.warning("webhook_failed", delivery_id=str(delivery.id), attempts=new_attempts, error=str(exc))

        from sqlalchemy import update
        await db.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == delivery.id)
            .values(
                status=status,
                attempts=delivery.attempts + 1,
                last_attempted_at=now,
                updated_at=now,
            )
        )
        await db.commit()

def _backoff_time(attempts: int) -> float:
    return min((attempts ** 2) * 30, 3600)
```

- [ ] **Step 2: Commit**

```bash
git add worker/worker/webhook_sender.py
git commit -m "feat: add webhook retry sender with exponential backoff"
```

---

## Task 6: Seeder

**Files:**
- Create: `worker/worker/seeder.py`
- Create: `decoders/linux_auth_failed.yaml`
- Create: `decoders/linux_sudo.yaml`
- Create: `decoders/nginx_access.yaml`
- Create: `decoders/generic_syslog.yaml`
- Create: `rules/ssh_failed_login.yaml`
- Create: `rules/ssh_brute_force.yaml`
- Create: `rules/sudo_executed.yaml`
- Create: `rules/nginx_suspicious_path.yaml`
- Create: `rules/access_env_file.yaml`
- Create: `rules/access_etc_passwd.yaml`
- Create: `rules/wordpress_admin_probe.yaml`

- [ ] **Step 1: Write seeder.py**

```python
# worker/worker/seeder.py
import glob
import os
import yaml
import structlog
from sqlalchemy import func, select
from worker.config import DECODERS_DIR, RULES_DIR
from worker.database import AsyncSessionLocal
from worker.models import Decoder, Rule

log = structlog.get_logger()

async def seed_if_empty() -> None:
    async with AsyncSessionLocal() as db:
        decoder_count = (await db.execute(select(func.count()).select_from(Decoder))).scalar()
        if decoder_count == 0:
            await _seed_decoders(db)
        rule_count = (await db.execute(select(func.count()).select_from(Rule))).scalar()
        if rule_count == 0:
            await _seed_rules(db)
        await db.commit()

async def _seed_decoders(db) -> None:
    pattern = os.path.join(DECODERS_DIR, "*.yaml")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as f:
                content = f.read()
            d = yaml.safe_load(content)
            db.add(Decoder(
                name=d["name"],
                log_type=d["log_type"],
                content=content,
                priority=d.get("priority", 100),
                is_enabled=d.get("enabled", True),
            ))
            log.info("decoder_seeded", name=d["name"])
        except Exception as exc:
            log.error("decoder_seed_failed", path=path, error=str(exc))

async def _seed_rules(db) -> None:
    pattern = os.path.join(RULES_DIR, "*.yaml")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as f:
                content = f.read()
            d = yaml.safe_load(content)
            db.add(Rule(
                title=d.get("title", "Untitled"),
                description=d.get("description"),
                content=content,
                level=d.get("level", "medium"),
                tags=d.get("tags", []),
                mitre_tags=[t for t in d.get("tags", []) if t.startswith("attack.")],
                is_enabled=True,
                group_id=None,
            ))
            log.info("rule_seeded", title=d.get("title"))
        except Exception as exc:
            log.error("rule_seed_failed", path=path, error=str(exc))
```

- [ ] **Step 2: Write decoder YAML files**

```yaml
# decoders/linux_auth_failed.yaml
name: linux_auth_failed
log_type: linux_auth
type: regex
priority: 10
enabled: true
pattern: 'Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)'
fields:
  event.category: authentication
  event.action: login_failed
  source.ip: src_ip
  user.name: user
  source.port: port
```

```yaml
# decoders/linux_sudo.yaml
name: linux_sudo
log_type: linux_auth
type: regex
priority: 20
enabled: true
pattern: '(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<run_as>\S+)\s*;\s*COMMAND=(?P<cmd>.+)'
fields:
  event.category: process
  event.action: sudo_command
  user.name: user
  process.command_line: cmd
  process.working_directory: pwd
```

```yaml
# decoders/nginx_access.yaml
name: nginx_access
log_type: nginx_access
type: regex
priority: 10
enabled: true
pattern: '(?P<src_ip>\S+)\s+-\s+-\s+\[.*?\]\s+"(?P<method>\S+)\s+(?P<request>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\d+)'
fields:
  event.category: web
  event.action: http_request
  source.ip: src_ip
  http.request.method: method
  url.path: request
  http.response.status_code: status
```

```yaml
# decoders/generic_syslog.yaml
name: generic_syslog
log_type: syslog
type: regex
priority: 200
enabled: true
pattern: '(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?\:\s+(?P<message>.+)'
fields:
  event.category: system
  event.action: syslog_message
  host.hostname: host
  process.name: program
  message: message
```

- [ ] **Step 3: Write rule YAML files**

```yaml
# rules/ssh_failed_login.yaml
title: SSH Failed Login
id: rule-ssh-failed-login
description: Single failed SSH login attempt detected
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1110
```

```yaml
# rules/ssh_brute_force.yaml
title: SSH Brute Force Attack
id: rule-ssh-brute-force
description: Multiple failed SSH logins from same source IP
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
threshold:
  count: 5
  timewindow: 300
  group_by: source.ip
suppression:
  timewindow: 3600
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
```

```yaml
# rules/sudo_executed.yaml
title: Sudo Command Executed
id: rule-sudo-executed
description: A user executed a command via sudo
logsource:
  product: linux
detection:
  selection:
    event.action: sudo_command
  condition: selection
level: low
tags:
  - attack.privilege_escalation
  - attack.t1548.003
```

```yaml
# rules/nginx_suspicious_path.yaml
title: Nginx Suspicious Path Access
id: rule-nginx-suspicious-path
description: HTTP request to commonly exploited path
logsource:
  product: nginx
detection:
  selection:
    url.path|contains:
      - "../"
      - "..%2F"
      - "%2e%2e"
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1083
```

```yaml
# rules/access_env_file.yaml
title: Access to .env File
id: rule-access-env-file
description: HTTP request targeting .env configuration file
logsource:
  product: nginx
detection:
  selection:
    url.path|contains: ".env"
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1552.001
```

```yaml
# rules/access_etc_passwd.yaml
title: Access to /etc/passwd
id: rule-access-etc-passwd
description: HTTP request targeting /etc/passwd (path traversal attempt)
logsource:
  product: nginx
detection:
  selection:
    url.path|contains: "etc/passwd"
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1552
```

```yaml
# rules/wordpress_admin_probe.yaml
title: WordPress Admin Login Probing
id: rule-wordpress-admin-probe
description: Repeated requests to WordPress admin login page
logsource:
  product: nginx
detection:
  selection:
    url.path|contains: "wp-admin"
  condition: selection
threshold:
  count: 10
  timewindow: 60
  group_by: source.ip
suppression:
  timewindow: 3600
level: medium
tags:
  - attack.credential_access
  - attack.t1110
```

- [ ] **Step 4: Commit**

```bash
git add worker/worker/seeder.py decoders/ rules/
git commit -m "feat: add seeder, sample decoders, and sample Sigma rules"
```

---

## Task 7: Consumer Loop

**Files:**
- Create: `worker/worker/consumer.py`

- [ ] **Step 1: Write consumer.py**

```python
# worker/worker/consumer.py
import asyncio
import json
import socket
import uuid
from datetime import datetime, timezone
import structlog
from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from worker.config import REDIS_CONSUMER_GROUP, REDIS_STREAM_KEY
from worker.database import AsyncSessionLocal
from worker.decoder_engine import DecoderEngine
from worker.models import Event, RawLog
from worker.redis_client import get_redis
from worker.sigma_engine import SigmaEngine
from worker.alert_manager import create_alert

log = structlog.get_logger()
CONSUMER_NAME = f"worker-{socket.gethostname()}"

logs_ingested   = Counter("siem_logs_ingested_total", "Total logs ingested")
events_decoded  = Counter("siem_events_decoded_total", "Total events decoded")
decode_failures = Counter("siem_decode_failures_total", "Total decode failures")
alerts_total    = Counter("siem_alerts_generated_total", "Alerts generated", ["severity"])
sigma_matches   = Counter("siem_sigma_matches_total", "Sigma rule matches", ["rule_id"])

async def ensure_stream_group(redis) -> None:
    try:
        await redis.xgroup_create(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, id="0", mkstream=True)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            raise

async def load_engines(db: AsyncSession) -> tuple[DecoderEngine, SigmaEngine]:
    from sqlalchemy import select
    from worker.models import Decoder, Rule

    result = await db.execute(select(Decoder).where(Decoder.is_enabled == True).order_by(Decoder.priority))
    decoder_yamls = [d.content for d in result.scalars().all()]
    dec_engine = DecoderEngine()
    dec_engine.load_from_yaml_list(decoder_yamls)

    result = await db.execute(select(Rule).where(Rule.is_enabled == True))
    rule_yamls = [r.content for r in result.scalars().all()]
    sig_engine = SigmaEngine()
    sig_engine.load_from_yaml_list(rule_yamls)

    return dec_engine, sig_engine

async def process_message(
    data: dict,
    dec_engine: DecoderEngine,
    sig_engine: SigmaEngine,
) -> None:
    agent_id_str = data.get("agent_id")
    log_type = data.get("log_type", "")
    raw_message = data.get("raw_message", "")
    received_at_str = data.get("received_at", "")
    hostname = data.get("hostname", "unknown")
    group_id = data.get("group_id", "default")

    try:
        received_at = datetime.fromisoformat(received_at_str)
    except Exception:
        received_at = datetime.now(timezone.utc)

    agent_id = uuid.UUID(agent_id_str) if agent_id_str else None

    async with AsyncSessionLocal() as db:
        raw_log = RawLog(agent_id=agent_id, log_type=log_type, raw_message=raw_message, received_at=received_at)
        db.add(raw_log)
        await db.flush()

        decoded = dec_engine.decode(log_type, raw_message)
        if not decoded:
            decode_failures.inc()

        event = Event(
            raw_log_id=raw_log.id,
            agent_id=agent_id,
            group_id=group_id,
            decoded_fields=decoded,
            event_category=decoded.get("event.category"),
            event_action=decoded.get("event.action"),
            source_ip=decoded.get("source.ip"),
            user_name=decoded.get("user.name"),
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)

    logs_ingested.inc()
    events_decoded.inc()

    flat_event = {**decoded, "group_id": group_id, "hostname": hostname}
    rule_matches = sig_engine.evaluate(flat_event)
    for match in rule_matches:
        sigma_matches.labels(rule_id=match["id"]).inc()
        alerts_total.labels(severity=match["level"]).inc()
        await create_alert(
            rule_match=match,
            event_id=event.id,
            agent_id=agent_id,
            group_id=group_id,
            source_ip=decoded.get("source.ip"),
            hostname=hostname,
        )
        log.info("alert_generated", title=match["title"], severity=match["level"], source_ip=decoded.get("source.ip"))

async def consume_loop(dec_engine: DecoderEngine, sig_engine: SigmaEngine) -> None:
    redis = await get_redis()
    await ensure_stream_group(redis)

    while True:
        try:
            messages = await redis.xreadgroup(
                REDIS_CONSUMER_GROUP, CONSUMER_NAME,
                {REDIS_STREAM_KEY: ">"}, count=10, block=5000
            )
            if not messages:
                continue
            for _stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        await process_message(data, dec_engine, sig_engine)
                        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                    except Exception as exc:
                        log.error("message_processing_failed", msg_id=msg_id, error=str(exc))
                        await redis.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, msg_id)
                        await redis.xadd(f"{REDIS_STREAM_KEY}:failed", data)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("consume_loop_error", error=str(exc))
            await asyncio.sleep(5)

async def reload_loop(state: dict) -> None:
    from worker.config import RELOAD_INTERVAL
    while True:
        await asyncio.sleep(RELOAD_INTERVAL)
        try:
            async with AsyncSessionLocal() as db:
                dec_engine, sig_engine = await load_engines(db)
            state["dec_engine"] = dec_engine
            state["sig_engine"] = sig_engine
            log.info("engines_reloaded")
        except Exception as exc:
            log.error("reload_failed", error=str(exc))
```

- [ ] **Step 2: Commit**

```bash
git add worker/worker/consumer.py
git commit -m "feat: add Redis Streams consumer loop with decode + sigma + alert pipeline"
```

---

## Task 8: Main Entry Point & Health Server

**Files:**
- Create: `worker/worker/main.py`

- [ ] **Step 1: Write main.py**

```python
# worker/worker/main.py
import asyncio
import time
import logging
import structlog
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest
import redis.asyncio as aioredis

from worker.config import LOG_LEVEL, REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP
from worker.database import AsyncSessionLocal, engine
from worker.decoder_engine import DecoderEngine
from worker.redis_client import get_redis
from worker.seeder import seed_if_empty
from worker.sigma_engine import SigmaEngine
from worker.consumer import consume_loop, load_engines, reload_loop
from worker.webhook_sender import webhook_retry_loop

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.getLevelName(LOG_LEVEL.upper())
    ),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
log = structlog.get_logger()

_start_time = time.time()
queue_lag_gauge = Gauge("siem_worker_queue_lag", "Redis stream pending messages")
active_agents_gauge = Gauge("siem_active_agents", "Active agents count")

class HealthHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/metrics":
            body = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

def start_health_server():
    server = HTTPServer(("0.0.0.0", 8001), HealthHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    log.info("health_server_started", port=8001)

async def main():
    log.info("worker_starting")
    start_health_server()

    await seed_if_empty()

    async with AsyncSessionLocal() as db:
        dec_engine, sig_engine = await load_engines(db)

    state = {"dec_engine": dec_engine, "sig_engine": sig_engine}
    log.info("engines_loaded", decoders=len(dec_engine._decoders), rules=len(sig_engine._rules))

    async def _consume():
        while True:
            await consume_loop(state["dec_engine"], state["sig_engine"])

    await asyncio.gather(
        _consume(),
        reload_loop(state),
        webhook_retry_loop(),
    )

if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Commit**

```bash
git add worker/worker/main.py
git commit -m "feat: add worker main entry point with health server and task orchestration"
```

---

## Task 9: End-to-End Worker Test

- [ ] **Step 1: Start all services**

```bash
docker compose up -d postgres redis server-api
sleep 10
```

- [ ] **Step 2: Run worker locally**

```bash
cd worker
DATABASE_URL="postgresql+asyncpg://soc:soc@localhost:5432/soc_platform" \
  REDIS_URL="redis://localhost:6379/0" \
  DECODERS_DIR="../decoders" \
  RULES_DIR="../rules" \
  python -m worker.main &
sleep 5
```

- [ ] **Step 3: Push a test log to Redis**

```bash
python3 -c "
import redis, json
r = redis.from_url('redis://localhost:6379/0')
r.xadd('siem:logs', {
  'agent_id': '00000000-0000-0000-0000-000000000001',
  'group_id': 'default',
  'hostname': 'test-host',
  'log_type': 'linux_auth',
  'raw_message': 'May 21 10:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2',
  'received_at': '2026-05-21T10:00:00+00:00',
})
print('pushed')
"
```

- [ ] **Step 4: Verify alert created**

```bash
sleep 3
psql postgresql://soc:soc@localhost:5432/soc_platform -c "SELECT title, severity, status, source_ip FROM alerts LIMIT 5;"
```

Expected: Row with `title=SSH Failed Login`, `severity=medium`, `status=new`, `source_ip=1.2.3.4`

- [ ] **Step 5: Check worker health**

```bash
curl -s http://localhost:8001/health
```

Expected: `{"status":"ok"}`

- [ ] **Step 6: Commit**

```bash
kill %1 2>/dev/null || true
git add -A
git commit -m "feat: complete worker pipeline - end-to-end log → alert verified"
```
