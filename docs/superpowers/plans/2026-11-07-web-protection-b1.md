# Web Protection (Stage B1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Server-side Web Protection: per-group domain blocklist with manual block/unblock, allowlist (with built-ins), per-group policy and custom block page, the agent delta-sync endpoint, and a dashboard page — everything agents (stage B2) need.

**Architecture:** Three Postgres tables share one sequence `web_block_seq` so agents sync deltas like the malware-hash set. Domain normalisation lives in one stdlib-only worker module copied into the API image. Block page HTML is sanitised with `nh3` on save; CSS from `<style>` blocks is cleaned separately. The heartbeat carries `web_blocklist_version`; agents fetch `/api/ingest/web-blocklist`.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async, PostgreSQL, `nh3==0.3.7` (new), React 18 + TypeScript + TanStack Query + Tailwind.

**Spec:** `docs/superpowers/specs/2026-11-07-threat-iocs-web-protection-design.md` (section B1; B2/B3 are later stages)

## Global Constraints

- Group scoping is mandatory: every dashboard query filters by `get_scoped_group()` (None = superadmin). Non-superadmins see their group's rows plus global (`*`) rows; they change only their group's rows.
- Read permission `alerts:read`; every change `agents:manage`. Every change is audit-logged (`app.services.audit.audit_log`).
- Web Protection is **off** per group by default (`enabled=false`, `feed_enabled=false`, `alert_enabled=false`); agents of a disabled group get version `""`.
- Global (feed) rows use `group_id = "*"`; group fallback for policies is `"default"`.
- Every insert/update of `web_block_entries` and `web_block_policies` takes `web_block_seq.next_value()`; every allowlist change bumps the platform setting `web_block_rules_seq` (forces agent resync).
- IP literals are never web-blocked (409/422 with a message); domains are lowercased, trailing dot stripped, IDNA/punycode, ≤ 253 chars, labels `[a-z0-9-]{1,63}` not starting/ending with `-`.
- Block page: ≤ 256 KB; no `script`, `iframe`, `object`, `embed`, `form`, `on*` attributes, `javascript:`/`vbscript:` URLs; images only `data:image/…`; CSS from `<style>` blocks kept but without `<`, `@import`, non-data `url()`, `expression(`.
- Variables: `{{domain}}`, `{{reason}}`, `{{source}}`, `{{time}}`, `{{hostname}}`, `{{contact}}`, HTML-escaped at render.
- New dependency allowed: `nh3==0.3.7` in `server-api/requirements.txt` only.
- CI pins `pytest==8.3.4`, `pytest-asyncio==0.24.0`. Server-api async test modules add the autouse fixture `asyncio.set_event_loop(event_loop)` (see `tests/server-api/test_malware_hashes.int.py:22-25`).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

### Test commands

```bash
docker run -d --rm --name adsiem-testpg-sdd -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc -e POSTGRES_DB=test -p 55433:5432 pgvector/pgvector:pg16   # if not running
export JWT_SECRET=ci-test-secret-0123456789abcdef0123456789abcdef
export TEST_DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test DATABASE_URL=postgresql+asyncpg://soc:soc@localhost:55433/test
python3 -m venv --system-site-packages /tmp/adsiem-ci-venv && /tmp/adsiem-ci-venv/bin/pip install -q pytest==8.3.4 pytest-asyncio==0.24.0 nh3==0.3.7
PY=/tmp/adsiem-ci-venv/bin/python
```

## File Structure

| File | Responsibility |
|---|---|
| `worker/worker/web_domains.py` (create) | `normalize()`, `allow_match()`, `BUILTIN_ALLOWLIST`, `DomainError` — stdlib only |
| `server-api/Dockerfile`, `server-api/Dockerfile.dockerignore` (modify) | copy `web_domains.py` into the API image |
| `server-api/app/models/models.py` (modify) | `WebBlockEntry`, `WebAllowRule`, `WebBlockPolicy`, `_web_block_seq` |
| `server-api/app/services/web_page.py` (create) | block page sanitise / render / default template |
| `server-api/app/services/web_blocks.py` (create) | policy, allowlist, expiry, versions, agent delta, built-in seeding, blocked lookup |
| `server-api/app/api/routes/web_protection.py` (create) | dashboard API + agent sync route |
| `server-api/app/api/routes/ingest.py`, `server-api/app/schemas/schemas.py` (modify) | heartbeat `web_blocklist_version` |
| `server-api/app/api/routes/iocs.py` (modify) | fill `blocked` for domain/url rows |
| `server-api/app/main.py` (modify) | register routers, seed built-in allowlist at start |
| `dashboard/src/hooks/useWebProtection.ts`, `dashboard/src/pages/WebProtectionPage.tsx` (create) | the page |
| `dashboard/src/pages/ThreatIocsPage.tsx`, `dashboard/src/hooks/useIocs.ts`, `App.tsx`, `AppSidebar.tsx` (modify) | Block web action, status column, route, menu |

---

### Task 1: Domain normalisation and allowlist matching

**Files:**
- Create: `worker/worker/web_domains.py`
- Modify: `server-api/Dockerfile:32` (COPY list), `server-api/Dockerfile.dockerignore` (after `!worker/worker/malware_hashes.py`)
- Test: `tests/worker/test_web_domains.py`

**Interfaces:**
- Produces: `class DomainError(ValueError)`, `normalize(value: str) -> str`, `allow_match(domain: str, rules: Iterable[tuple[str, bool]]) -> str | None`, `BUILTIN_ALLOWLIST: tuple[tuple[str, bool], ...]`, `MAX_DOMAIN = 253`.

- [ ] **Step 1: Write the failing tests** — `tests/worker/test_web_domains.py`:

```python
# tests/worker/test_web_domains.py
"""Web Protection domain rules (worker/web_domains.py), shared with server-api."""
import pytest

from worker.web_domains import BUILTIN_ALLOWLIST, DomainError, allow_match, normalize


@pytest.mark.parametrize("value,expected", [
    ("evil.example", "evil.example"),
    ("EVIL.Example.", "evil.example"),
    ("https://user:pw@Evil.example:8443/path?q=1", "evil.example"),
    ("evil.example/path", "evil.example"),
    ("evil.example:8080", "evil.example"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("http://bücher.example/a", "xn--bcher-kva.example"),
    ("  sub.evil.example  ", "sub.evil.example"),
])
def test_normalize(value, expected):
    assert normalize(value) == expected


@pytest.mark.parametrize("value", [
    "", "   ", "localhost", "45.33.32.156", "http://45.33.32.156/a", "[2001:4860::8888]",
    "http://[2001:4860::8888]/", "-bad.example", "a..example", "x" * 64 + ".example", "ex ample.com", "http://",
])
def test_normalize_rejects(value):
    with pytest.raises(DomainError):
        normalize(value)


def test_ip_rejection_says_why():
    with pytest.raises(DomainError, match="IP addresses cannot be web-blocked"):
        normalize("45.33.32.156")


def test_allow_match_apex_and_subdomains():
    rules = [("github.com", True), ("weebly.com", False)]
    assert allow_match("github.com", rules) == "github.com"
    assert allow_match("raw.github.com", rules) == "github.com"
    assert allow_match("weebly.com", rules) == "weebly.com"
    assert allow_match("evil.weebly.com", rules) is None
    assert allow_match("notgithub.com", rules) is None


def test_builtin_allowlist_is_normalized():
    for domain, _ in BUILTIN_ALLOWLIST:
        assert normalize(domain) == domain
    assert ("github.com", True) in BUILTIN_ALLOWLIST
    assert ("weebly.com", False) in BUILTIN_ALLOWLIST
    assert len({d for d, _ in BUILTIN_ALLOWLIST}) == len(BUILTIN_ALLOWLIST)
```

- [ ] **Step 2: Run to verify failure** — `python3 -m pytest tests/worker/test_web_domains.py -q` → `ModuleNotFoundError: No module named 'worker.web_domains'`.

- [ ] **Step 3: Implement** — `worker/worker/web_domains.py`:

```python
# worker/worker/web_domains.py
"""Web Protection domain rules, shared by the worker (feeds, alert auto-block)
and server-api (manual blocks, agent sync). Standard library only: the
server-api image copies this one file (server-api/Dockerfile)."""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from urllib.parse import urlsplit

MAX_DOMAIN = 253
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# (domain, include_subdomains). Shared hosting whose subdomains belong to one
# tenant protects only the apex, so evil.weebly.com stays blockable.
BUILTIN_ALLOWLIST: tuple[tuple[str, bool], ...] = (
    ("github.com", True), ("githubusercontent.com", True), ("google.com", True),
    ("googleusercontent.com", True), ("googleapis.com", True), ("gstatic.com", True),
    ("microsoft.com", True), ("live.com", True), ("office.com", True), ("sharepoint.com", True),
    ("windows.net", True), ("dropbox.com", True), ("dropboxusercontent.com", True),
    ("discordapp.com", True), ("discord.com", True), ("amazonaws.com", True), ("cloudfront.net", True),
    ("apple.com", True), ("icloud.com", True), ("cloudflare.com", True), ("akamaized.net", True),
    ("weebly.com", False), ("wixsite.com", False), ("blogspot.com", False), ("wordpress.com", False),
    ("000webhostapp.com", False), ("netlify.app", False), ("vercel.app", False), ("pages.dev", False),
    ("web.app", False), ("firebaseapp.com", False), ("herokuapp.com", False),
)


class DomainError(ValueError):
    """Why a value cannot be web-blocked; the message is shown to the analyst."""


def normalize(value: str) -> str:
    """Domain from a bare domain or URL: lowercase, no trailing dot, punycode."""
    raw = str(value or "").strip()
    if not raw:
        raise DomainError("Enter a domain or URL")
    if "://" in raw:
        try:
            host = urlsplit(raw).hostname or ""
        except ValueError as exc:
            raise DomainError("Not a valid URL") from exc
    else:
        host = raw.split("/", 1)[0].rsplit("@", 1)[-1]
        if host.count(":") == 1:
            host = host.split(":", 1)[0]
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise DomainError("IP addresses cannot be web-blocked; block the IP on the firewall instead")
    if "." not in host:
        raise DomainError("A domain needs at least two labels, like example.com")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainError("Not a valid domain name") from exc
    if len(ascii_host) > MAX_DOMAIN or not all(_LABEL.match(label) for label in ascii_host.split(".")):
        raise DomainError("Not a valid domain name")
    return ascii_host


def allow_match(domain: str, rules: Iterable[tuple[str, bool]]) -> str | None:
    """The allowlist rule (domain) that covers `domain`, or None."""
    for rule, include_subdomains in rules:
        if domain == rule or (include_subdomains and domain.endswith("." + rule)):
            return rule
    return None
```

Append ` worker/worker/web_domains.py` to the `COPY worker/worker/__init__.py … malware_hashes.py ./worker/` line in `server-api/Dockerfile`, and add `!worker/worker/web_domains.py` on the line after `!worker/worker/malware_hashes.py` in `server-api/Dockerfile.dockerignore`.

- [ ] **Step 4: Verify** — `python3 -m pytest tests/worker/test_web_domains.py -q` → all pass (24).

- [ ] **Step 5: Commit** — `feat(webblock): domain normalisation and allowlist matching`.

---

### Task 2: Tables and block page sanitising

**Files:**
- Modify: `server-api/app/models/models.py` (append after `MalwareHash`)
- Modify: `server-api/requirements.txt` (add `nh3==0.3.7`)
- Create: `server-api/app/services/web_page.py`
- Test: `tests/server-api/test_web_page.py`

**Interfaces:**
- Produces: models `WebBlockEntry`, `WebAllowRule`, `WebBlockPolicy`, sequence `_web_block_seq`; `web_page.DEFAULT_PAGE_HTML`, `VARIABLES`, `SAMPLE: dict`, `MAX_PAGE_BYTES`, `class PageError(ValueError)`, `sanitize(page_html: str) -> str`, `render(page_html: str, values: dict) -> str`, `document(page_html: str, values: dict) -> str`.

- [ ] **Step 1: Write the failing tests** — `tests/server-api/test_web_page.py`:

```python
# tests/server-api/test_web_page.py
"""Block page HTML (services/web_page.py): no script survives saving; variables
are escaped at render."""
import pytest

from app.services import web_page as wp


def test_script_tags_and_handlers_are_removed():
    out = wp.sanitize('<p>hi</p><script>alert(1)</script><img src="data:image/png;base64,AA" onerror="x()">')
    assert "<p>hi</p>" in out and "<script" not in out and "onerror" not in out
    assert 'src="data:image/png;base64,AA"' in out


@pytest.mark.parametrize("html,forbidden", [
    ('<a href="javascript:alert(1)">x</a>', "javascript"),
    ('<a href="data:text/html,x">x</a>', "data:"),
    ('<img src="https://tracker.example/p.gif">', "tracker.example"),
    ('<iframe src="https://x.example"></iframe>', "iframe"),
    ('<object data="x"></object>', "object"),
    ('<form action="https://x.example"><input></form>', "form"),
])
def test_dangerous_markup_is_dropped(html, forbidden):
    assert forbidden not in wp.sanitize(html)


def test_style_blocks_are_kept_but_cleaned():
    out = wp.sanitize('<style>body{color:red} @import url(http://x.example/a.css); '
                      '.a{background:url(http://x.example/i.png)}</style><p>x</p>')
    assert out.startswith("<style>") and "color:red" in out
    assert "@import" not in out and "x.example" not in out and "<p>x</p>" in out


def test_style_cannot_break_out_into_script():
    out = wp.sanitize('<style>a{content:"</style><script>alert(1)</script>"}</style>')
    assert "<script" not in out


def test_variables_survive_sanitising():
    assert "{{domain}}" in wp.sanitize("<p>{{domain}}</p>")
    default = wp.sanitize(wp.DEFAULT_PAGE_HTML)
    assert "{{domain}}" in default and "<main>" in default


def test_oversized_page_is_rejected():
    with pytest.raises(wp.PageError):
        wp.sanitize("<p>" + "a" * (wp.MAX_PAGE_BYTES + 1) + "</p>")


def test_render_escapes_values_and_keeps_unknown_placeholders():
    assert wp.render("<p>{{ domain }}</p>{{other}}", {"domain": "<b>x</b>"}) == "<p>&lt;b&gt;x&lt;/b&gt;</p>{{other}}"


def test_document_wraps_a_full_page():
    doc = wp.document("<p>{{domain}}</p>", wp.SAMPLE)
    assert doc.startswith("<!doctype html>") and wp.SAMPLE["domain"] in doc and '<meta charset="utf-8">' in doc
```

- [ ] **Step 2: Run to verify failure** — `$PY -m pytest tests/server-api/test_web_page.py -q` → `ImportError` (no `web_page`).

- [ ] **Step 3: Implement**

Add `nh3==0.3.7` to `server-api/requirements.txt` (alphabetical position if the file is sorted, else at the end).

Append to `server-api/app/models/models.py` after the `MalwareHash` class:

```python
_web_block_seq = Sequence("web_block_seq")


class WebBlockEntry(Base):
    """A domain the agents of a group block (group_id "*" = feed entry for every
    group that enables feeds). Every change takes the next web_block_seq so
    agents sync deltas (app/services/web_blocks.py)."""
    __tablename__ = "web_block_entries"
    __table_args__ = (UniqueConstraint("group_id", "domain", "source", name="uq_web_block_entry"),)
    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain            = Column(String(253), nullable=False, index=True)
    group_id          = Column(String(100), nullable=False)
    source            = Column(String(20), nullable=False)        # manual, alert, urlhaus, phishtank
    status            = Column(String(20), nullable=False, default="active")  # active, removed, suppressed
    reason            = Column(Text, nullable=False, default="")
    sample_url        = Column(Text)
    alert_id          = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"))
    created_by        = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at        = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at        = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
    expires_at        = Column(DateTime(timezone=True))
    last_seen_in_feed = Column(DateTime(timezone=True))
    seq               = Column(BigInteger, _web_block_seq, server_default=_web_block_seq.next_value(),
                               nullable=False, index=True)


class WebAllowRule(Base):
    """Domains never web-blocked for a group ("*" = every group; built-ins)."""
    __tablename__ = "web_allowlist"
    __table_args__ = (UniqueConstraint("group_id", "domain", name="uq_web_allow_rule"),)
    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id           = Column(String(100), nullable=False)
    domain             = Column(String(253), nullable=False)
    include_subdomains = Column(Boolean, nullable=False, default=False)
    builtin            = Column(Boolean, nullable=False, default=False)
    enabled            = Column(Boolean, nullable=False, default=True)
    created_by         = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at         = Column(DateTime(timezone=True), nullable=False, default=now_utc)


class WebBlockPolicy(Base):
    """Per-group Web Protection switches and block page; "default" is the fallback."""
    __tablename__ = "web_block_policies"
    group_id         = Column(String(100), primary_key=True)
    enabled          = Column(Boolean, nullable=False, default=False)
    feed_enabled     = Column(Boolean, nullable=False, default=False)
    alert_enabled    = Column(Boolean, nullable=False, default=False)
    alert_block_days = Column(Integer, nullable=False, default=30)
    max_entries      = Column(Integer, nullable=False, default=50000)
    page_html        = Column(Text)  # None = built-in page
    contact          = Column(String(255), nullable=False, default="")
    updated_at       = Column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
    seq              = Column(BigInteger, _web_block_seq, server_default=_web_block_seq.next_value(), nullable=False)
```

Create `server-api/app/services/web_page.py`:

```python
# server-api/app/services/web_page.py
"""The Web Protection block page. Saved HTML is sanitised here (nh3 for markup;
<style> blocks are cleaned separately because nh3 drops them). Agents render it
like render()/document() below and serve it with a strict CSP (stage B2)."""
from __future__ import annotations

import html as _html
import re

import nh3

MAX_PAGE_BYTES = 256 * 1024
VARIABLES = ("domain", "reason", "source", "time", "hostname", "contact")
SAMPLE = {"domain": "malicious.example", "reason": "Listed by URLhaus as malware distribution",
          "source": "urlhaus", "time": "2026-11-07 10:00 UTC", "hostname": "WS-0142",
          "contact": "the security team"}

DEFAULT_PAGE_HTML = """<style>
body{margin:0;font-family:system-ui,sans-serif;background:#0b1220;color:#e5e7eb;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:560px;padding:32px}
h1{font-size:24px;margin:0 0 12px}
p{line-height:1.5;color:#cbd5e1}
code{background:#1f2937;padding:2px 6px;border-radius:4px}
small{color:#94a3b8}
</style>
<main>
<h1>This site is blocked</h1>
<p>Access to <code>{{domain}}</code> was blocked by your organisation's security policy.</p>
<p>Reason: {{reason}}</p>
<p><small>Source: {{source}} · Host: {{hostname}} · {{time}}</small></p>
<p>If you need this site for your work, contact {{contact}}.</p>
</main>"""

_STYLE = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.I | re.S)
_IMPORT = re.compile(r"@import[^;]*;?", re.I)
_CSS_URL = re.compile(r"url\(\s*(?!['\"]?data:image/)[^)]*\)", re.I)
_EXPRESSION = re.compile(r"expression\s*\(", re.I)
_VAR = re.compile(r"\{\{\s*(" + "|".join(VARIABLES) + r")\s*\}\}")
_TAGS = set(nh3.ALLOWED_TAGS) | {"main", "section", "header", "footer", "article", "span", "div", "small", "img"}
_ATTRIBUTES = {"*": {"class", "id", "style", "title", "lang", "dir"}, "a": {"href", "title"},
               "img": {"src", "alt", "width", "height"}}


class PageError(ValueError):
    """Why a block page cannot be saved; shown to the analyst."""


def _clean_css(css: str) -> str:
    css = css.replace("<", "")
    css = _IMPORT.sub("", css)
    css = _CSS_URL.sub("none", css)
    return _EXPRESSION.sub("", css).strip()


def _attribute_filter(tag: str, attr: str, value: str) -> str | None:
    lowered = value.strip().lower()
    if tag == "img" and attr == "src":
        return value if lowered.startswith("data:image/") else None
    if attr == "href" and lowered.startswith("data:"):
        return None
    return value


def sanitize(page_html: str) -> str:
    if len(page_html.encode()) > MAX_PAGE_BYTES:
        raise PageError("The block page is larger than 256 KB")
    css = "\n".join(c for c in (_clean_css(m) for m in _STYLE.findall(page_html)) if c)
    body = nh3.clean(_STYLE.sub("", page_html), tags=_TAGS, attributes=_ATTRIBUTES,
                     url_schemes={"https", "http", "mailto", "data"}, attribute_filter=_attribute_filter,
                     link_rel="noopener noreferrer")
    return (f"<style>\n{css}\n</style>\n" if css else "") + body


def render(page_html: str, values: dict) -> str:
    return _VAR.sub(lambda m: _html.escape(str(values.get(m.group(1), "")), quote=True), page_html)


def document(page_html: str, values: dict) -> str:
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Site blocked</title></head><body>{render(page_html, values)}</body></html>")
```

If `nh3.clean` rejects a tag in `_TAGS` (it raises if a tag is also in its default `clean_content_tags`), remove that tag from `_TAGS` and note it in the report.

- [ ] **Step 4: Verify** — `$PY -m pytest tests/server-api/test_web_page.py -q` → all pass (13). Also `$PY -c "import app.models.models"` from `server-api/` succeeds.

- [ ] **Step 5: Commit** — `feat(webblock): web protection tables and block page sanitising`.

---

### Task 3: Lists service, agent sync and heartbeat version

**Files:**
- Create: `server-api/app/services/web_blocks.py`
- Create: `server-api/app/api/routes/web_protection.py` (agent route only in this task)
- Modify: `server-api/app/schemas/schemas.py:284` (`HeartbeatResponse`), `server-api/app/api/routes/ingest.py:311`
- Modify: `server-api/app/main.py` (router import + list; seed call after `_migrate_malware_hashes_tlsh()`)
- Modify: spec section B1 "Agent sync endpoint" (path `/api/ingest/web-blocklist`, `X-Agent-Token`; the agent, not the server, applies `max_entries`)
- Test: `tests/server-api/test_web_blocks.int.py`

**Interfaces:**
- Consumes: Task 1 `allow_match`, `BUILTIN_ALLOWLIST`; Task 2 models and `DEFAULT_PAGE_HTML`.
- Produces (`app.services.web_blocks`): `FEED_GROUP = "*"`, `RULES_SEQ_KEY = "web_block_rules_seq"`, `POLICY_DEFAULTS: dict`, `invalidate()`, `next_seq()`, `async policy_for(db, group_id) -> dict` (keys of `POLICY_DEFAULTS` + `seq`, `custom_page`; `page_html` resolved to the default), `async allow_rules(db, group_id) -> list[tuple[str, bool]]`, `async mark_rules_changed(db)` (caller commits), `async seed_builtin_allowlist(db)`, `async expire(db) -> int`, `async agent_version(db, agent) -> str`, `async delta(db, group_id, since, continuing=False, limit=5000) -> dict` (`policy`, `seq`, `reset`, `more`, `changes`), `async blocked_domains(db, group_id | None, domains) -> set[str]`.
- Produces (`web_protection.agent_router`, prefix `/api/ingest`): `POST /api/ingest/web-blocklist {since, continuing}` → delta + `version`.

- [ ] **Step 1: Write the failing tests** — `tests/server-api/test_web_blocks.int.py`:

```python
# tests/server-api/test_web_blocks.int.py
"""Web Protection lists: per-group policy, allowlist, expiry, and the agent
delta sync (a removal propagates, other groups never leak, allowlist and
policy changes force a resync)."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from app.api.routes import web_protection as routes
from app.core.database import get_db
from app.models.models import WebAllowRule, WebBlockEntry, WebBlockPolicy
from app.services import web_blocks as wb
from worker.web_domains import BUILTIN_ALLOWLIST

BLUE = {"X-Agent-Token": "blue-token"}


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(routes.agent_router)
    app.dependency_overrides[get_db] = database
    wb.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api
    wb.invalidate()


async def add(env, domain, group="blue", source="manual", status="active", expires=None, reason="r"):
    async with env.sessions() as db:
        row = WebBlockEntry(domain=domain, group_id=group, source=source, status=status, expires_at=expires,
                            reason=reason)
        db.add(row)
        await db.commit()
        return row.id


async def set_status(env, entry_id, status):
    async with env.sessions() as db:
        row = await db.get(WebBlockEntry, entry_id)
        row.status, row.seq = status, wb.next_seq()
        await db.commit()
    wb.invalidate()


async def set_policy(env, group, **values):
    async with env.sessions() as db:
        row = await db.get(WebBlockPolicy, group) or WebBlockPolicy(group_id=group)
        for key, value in values.items():
            setattr(row, key, value)
        row.seq = wb.next_seq()
        db.add(row)
        await db.commit()
    wb.invalidate()


async def sync(env, since=0, headers=BLUE):
    r = await env.api.post("/api/ingest/web-blocklist", json={"since": since}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def apply(state, out):
    if out["reset"]:
        state = set()
    for c in out["changes"]:
        (state.add if c["action"] == "block" else state.discard)(c["domain"])
    return state


async def test_disabled_group_gets_nothing(env):
    await add(env, "evil.example")
    out = await sync(env)
    assert out["policy"]["enabled"] is False and out["changes"] == [] and out["version"] == ""
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert await wb.agent_version(db, agent) == ""


async def test_delta_sync_scopes_groups_and_propagates_removals(env):
    await set_policy(env, "blue", enabled=True)
    evil = await add(env, "evil.example")
    await add(env, "red-only.example", group="red")
    await add(env, "feed.example", group="*", source="urlhaus")
    out = await sync(env)
    state = apply(set(), out)
    assert state == {"evil.example"} and out["reset"] is True and out["version"] == str(out["seq"])
    assert out["policy"]["page_html"].startswith("<style>")
    await add(env, "second.example")
    await set_status(env, evil, "removed")
    out2 = await sync(env, out["seq"])
    assert out2["reset"] is False
    assert apply(state, out2) == {"second.example"}
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        assert await wb.agent_version(db, agent) == out2["version"]


async def test_allowlist_and_policy_changes_force_a_resync(env):
    await set_policy(env, "blue", enabled=True)
    await add(env, "second.example")
    await add(env, "feed.example", group="*", source="urlhaus")
    out = await sync(env)
    async with env.sessions() as db:
        db.add(WebAllowRule(group_id="blue", domain="second.example"))
        await wb.mark_rules_changed(db)
        await db.commit()
    out2 = await sync(env, out["seq"])
    assert out2["reset"] is True and apply(set(), out2) == set()
    await set_policy(env, "blue", feed_enabled=True)
    out3 = await sync(env, out2["seq"])
    assert out3["reset"] is True and apply(set(), out3) == {"feed.example"}


async def test_expired_entries_are_removed(env):
    await set_policy(env, "blue", enabled=True)
    entry = await add(env, "old.example", expires=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert apply(set(), await sync(env)) == set()
    async with env.sessions() as db:
        assert (await db.get(WebBlockEntry, entry)).status == "removed"


async def test_a_domain_stays_blocked_while_any_entry_is_active(env):
    await set_policy(env, "blue", enabled=True)
    await add(env, "dup.example", source="manual", reason="analyst")
    alert = await add(env, "dup.example", source="alert", reason="auto")
    out = await sync(env)
    await set_status(env, alert, "removed")
    out2 = await sync(env, out["seq"])
    assert out2["changes"] == [{"domain": "dup.example", "action": "block", "source": "manual", "reason": "analyst"}]


async def test_unapproved_agent_is_refused(env):
    async with env.sessions() as db:
        agent = await db.get(wb.Agent, env.agents["blue"])
        agent.approved = False
        await db.commit()
    r = await env.api.post("/api/ingest/web-blocklist", json={"since": 0}, headers=BLUE)
    assert r.status_code == 403


async def test_builtin_allowlist_seed_is_idempotent(env):
    async with env.sessions() as db:
        await wb.seed_builtin_allowlist(db)
        await wb.seed_builtin_allowlist(db)
        count = (await db.execute(select(func.count()).select_from(WebAllowRule).where(
            WebAllowRule.builtin.is_(True)))).scalar_one()
        assert count == len(BUILTIN_ALLOWLIST)
        assert ("github.com", True) in await wb.allow_rules(db, "blue")


async def test_blocked_domains_respects_group_policy_and_allowlist(env):
    await set_policy(env, "blue", enabled=True)
    await add(env, "evil.example")
    await add(env, "red.example", group="red")
    async with env.sessions() as db:
        await wb.seed_builtin_allowlist(db)
    await add(env, "github.com")
    async with env.sessions() as db:
        assert await wb.blocked_domains(db, "blue", ["evil.example", "red.example", "github.com"]) == {"evil.example"}
        assert await wb.blocked_domains(db, "red", ["red.example"]) == set()  # red has Web Protection off
        assert await wb.blocked_domains(db, None, ["evil.example", "red.example"]) == {"evil.example", "red.example"}
```

(`wb.Agent` works because `web_blocks.py` imports `Agent` from the models.)

- [ ] **Step 2: Run to verify failure** — `$PY -m pytest tests/server-api/test_web_blocks.int.py -q` → `ImportError` (no `web_blocks` / `web_protection`).

- [ ] **Step 3: Implement**

`server-api/app/services/web_blocks.py`:

```python
# server-api/app/services/web_blocks.py
"""Web Protection lists (spec B1): per-group blocklist, allowlist and policy,
and the agent delta sync. Entries and policies take the next web_block_seq on
every change; allowlist changes bump the platform setting web_block_rules_seq,
which forces every agent to resync (the allowlist filters the whole set)."""
from __future__ import annotations

import time

from sqlalchemy import func, or_, select, text, update

from app.models.models import Agent, PlatformSetting, WebAllowRule, WebBlockEntry, WebBlockPolicy, _web_block_seq
from app.services.web_page import DEFAULT_PAGE_HTML
from worker.web_domains import BUILTIN_ALLOWLIST, allow_match

FEED_GROUP = "*"
RULES_SEQ_KEY = "web_block_rules_seq"
POLICY_DEFAULTS = {"enabled": False, "feed_enabled": False, "alert_enabled": False, "alert_block_days": 30,
                   "max_entries": 50000, "page_html": None, "contact": ""}
SYNC_PAGE = 5000
CACHE_SECONDS = 30.0
_SOURCE_RANK = {"manual": 0, "alert": 1}

_version_cache: dict[str, tuple[float, str]] = {}


def invalidate() -> None:
    _version_cache.clear()


def next_seq():
    return _web_block_seq.next_value()


async def policy_for(db, group_id: str) -> dict:
    row = await db.get(WebBlockPolicy, group_id) or await db.get(WebBlockPolicy, "default")
    out = dict(POLICY_DEFAULTS)
    if row is not None:
        out.update({key: getattr(row, key) for key in POLICY_DEFAULTS})
    out["seq"] = int(row.seq) if row is not None else 0
    out["custom_page"] = out["page_html"] is not None
    if out["page_html"] is None:
        out["page_html"] = DEFAULT_PAGE_HTML
    return out


async def allow_rules(db, group_id: str) -> list[tuple[str, bool]]:
    rows = (await db.execute(select(WebAllowRule.domain, WebAllowRule.include_subdomains).where(
        WebAllowRule.enabled.is_(True), WebAllowRule.group_id.in_((group_id, FEED_GROUP))))).all()
    return [(domain, include) for domain, include in rows]


async def mark_rules_changed(db) -> None:
    """Call in the same transaction as an allowlist change; the caller commits."""
    seq = (await db.execute(select(next_seq()))).scalar_one()
    await db.merge(PlatformSetting(key=RULES_SEQ_KEY, value=str(seq), is_secret=False,
                                   description="Web Protection allowlist change marker"))
    invalidate()


async def _rules_seq(db) -> int:
    value = (await db.execute(select(PlatformSetting.value).where(PlatformSetting.key == RULES_SEQ_KEY))).scalar_one_or_none()
    try:
        return int(value or 0)
    except ValueError:
        return 0


async def seed_builtin_allowlist(db) -> None:
    for domain, include in BUILTIN_ALLOWLIST:
        await db.execute(text(
            "INSERT INTO web_allowlist (id, group_id, domain, include_subdomains, builtin, enabled, created_at) "
            "VALUES (gen_random_uuid(), :g, :d, :inc, true, true, now()) "
            "ON CONFLICT (group_id, domain) DO NOTHING"), {"g": FEED_GROUP, "d": domain, "inc": include})
    await db.commit()


async def expire(db) -> int:
    result = await db.execute(update(WebBlockEntry).where(
        WebBlockEntry.status == "active", WebBlockEntry.expires_at.is_not(None), WebBlockEntry.expires_at <= func.now(),
    ).values(status="removed", seq=next_seq(), updated_at=func.now()))
    if result.rowcount:
        await db.commit()
        invalidate()
    return result.rowcount or 0


def _groups(group_id: str, policy: dict) -> list[str]:
    return [group_id, FEED_GROUP] if policy["feed_enabled"] else [group_id]


async def _top_seq(db, group_id: str, policy: dict) -> int:
    entries = (await db.execute(select(func.coalesce(func.max(WebBlockEntry.seq), 0)).where(
        WebBlockEntry.group_id.in_(_groups(group_id, policy))))).scalar_one()
    return max(int(entries), await _rules_seq(db), policy["seq"])


async def agent_version(db, agent: Agent) -> str:
    """For the heartbeat: "" when off, else the newest relevant seq (cached briefly)."""
    if not agent.approved:
        return ""
    group = agent.group_id or "default"
    hit = _version_cache.get(group)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    await expire(db)
    policy = await policy_for(db, group)
    version = str(await _top_seq(db, group, policy)) if policy["enabled"] else ""
    _version_cache[group] = (time.monotonic(), version)
    return version


def _policy_out(policy: dict) -> dict:
    return {key: policy[key] for key in ("enabled", "page_html", "contact", "max_entries")}


async def _active(db, groups: list[str], domains: list[str] | None) -> dict[str, WebBlockEntry]:
    """Per domain, the active unexpired entry to report: manual over alert over feeds, newest first."""
    query = select(WebBlockEntry).where(
        WebBlockEntry.group_id.in_(groups), WebBlockEntry.status == "active",
        or_(WebBlockEntry.expires_at.is_(None), WebBlockEntry.expires_at > func.now()))
    if domains is not None:
        query = query.where(WebBlockEntry.domain.in_(domains))
    best: dict[str, WebBlockEntry] = {}
    for row in (await db.execute(query)).scalars().all():
        current = best.get(row.domain)
        key = (_SOURCE_RANK.get(row.source, 2), -row.created_at.timestamp())
        if current is None or key < (_SOURCE_RANK.get(current.source, 2), -current.created_at.timestamp()):
            best[row.domain] = row
    return best


async def delta(db, group_id: str, since: int, continuing: bool = False, limit: int = SYNC_PAGE) -> dict:
    """Changes above `since` for one group. reset: the agent drops its set first
    (first sync, allowlist/policy change, or a seq it cannot have); changes are
    then the active set. With more, the agent continues from seq with continuing=true."""
    await expire(db)
    policy = await policy_for(db, group_id)
    if not policy["enabled"]:
        return {"policy": _policy_out(policy), "seq": 0, "reset": True, "more": False, "changes": []}
    groups = _groups(group_id, policy)
    top = await _top_seq(db, group_id, policy)
    reset = not continuing and (since <= 0 or since > top or await _rules_seq(db) > since or policy["seq"] > since)
    if reset:
        since = 0
    rows = (await db.execute(select(WebBlockEntry.domain, WebBlockEntry.seq).where(
        WebBlockEntry.group_id.in_(groups), WebBlockEntry.seq > since).order_by(WebBlockEntry.seq).limit(limit))).all()
    more = len(rows) == limit
    domains = list(dict.fromkeys(domain for domain, _ in rows))
    active = await _active(db, groups, domains)
    rules = await allow_rules(db, group_id)
    changes = []
    for domain in domains:
        entry = active.get(domain)
        if entry is not None and allow_match(domain, rules) is None:
            changes.append({"domain": domain, "action": "block", "source": entry.source, "reason": entry.reason})
        elif not reset:
            changes.append({"domain": domain, "action": "remove"})
    return {"policy": _policy_out(policy), "seq": rows[-1].seq if more else top, "reset": reset, "more": more,
            "changes": changes}


async def blocked_domains(db, group_id: str | None, domains) -> set[str]:
    """Which of `domains` agents of `group_id` block (None = blocked for any group)."""
    domains = list(dict.fromkeys(domains))
    if not domains:
        return set()
    if group_id is None:
        rows = (await db.execute(select(WebBlockEntry.domain).where(
            WebBlockEntry.domain.in_(domains), WebBlockEntry.status == "active",
            or_(WebBlockEntry.expires_at.is_(None), WebBlockEntry.expires_at > func.now())))).scalars().all()
        return set(rows)
    policy = await policy_for(db, group_id)
    if not policy["enabled"]:
        return set()
    rules = await allow_rules(db, group_id)
    active = await _active(db, _groups(group_id, policy), domains)
    return {domain for domain in active if allow_match(domain, rules) is None}
```

`server-api/app/api/routes/web_protection.py` (Task 4 appends the dashboard router to this file):

```python
# server-api/app/api/routes/web_protection.py
"""Web Protection (spec B1): agents sync the blocklist here; the dashboard
manages the blocklist, allowlist, policy and block page."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_agent
from app.models.models import Agent
from app.services import web_blocks

agent_router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class DeltaRequest(BaseModel):
    since: int = 0
    continuing: bool = False


@agent_router.post("/web-blocklist")
async def agent_web_blocklist(
    body: DeltaRequest,
    agent: Annotated[Agent, Depends(get_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not agent.approved:
        raise HTTPException(status_code=403, detail="agent not approved")
    out = await web_blocks.delta(db, agent.group_id or "default", max(body.since, 0), body.continuing)
    # the version the agent stores once it has every page; equals the heartbeat's when caught up
    version = str(out["seq"]) if out["policy"]["enabled"] and not out["more"] else ""
    return {**out, "version": version}
```

If `get_agent` lives elsewhere than `app.core.deps`, import it from where `malware_hashes.py` imports it.

`server-api/app/schemas/schemas.py` — in `HeartbeatResponse`, after `malware_hashes_version`:

```python
    web_blocklist_version: str = ""  # "<seq>"; agents sync from /api/ingest/web-blocklist ("" = Web Protection off)
```

`server-api/app/api/routes/ingest.py` — import `from app.services import web_blocks` and add to the `HeartbeatResponse(...)` call after `malware_hashes_version=…`:

```python
        web_blocklist_version=await web_blocks.agent_version(db, agent),
```

`server-api/app/main.py` — import `from app.api.routes.web_protection import agent_router as web_protection_agent_router` with the other route imports, add `web_protection_agent_router,` to the `for router in [...]` list, and add after `await _migrate_malware_hashes_tlsh()`:

```python
        await _seed_web_allowlist()
```

with this helper next to `_migrate_malware_hashes_tlsh`:

```python
async def _seed_web_allowlist() -> None:
    from app.services.web_blocks import seed_builtin_allowlist
    async with AsyncSessionLocal() as db:
        await seed_builtin_allowlist(db)
```

(use the session factory name `main.py` already uses in its other helpers).

Spec edit, section B1 "Agent sync endpoint": change the path to `POST /api/ingest/web-blocklist` (agent-token header `X-Agent-Token`, like the malware-hash sync), and add: "The server sends the whole allowed set; the agent applies `max_entries` and the manual > alert > feed priority (B2)."

- [ ] **Step 4: Verify** — `$PY -m pytest tests/server-api/test_web_blocks.int.py tests/server-api/test_web_page.py -q` → all pass; then the heartbeat tests: `$PY -m pytest tests/server-api -q -k "heartbeat or ingest or malware"`.

- [ ] **Step 5: Commit** — `feat(webblock): per-group lists, agent delta sync and heartbeat version`.

---

### Task 4: Dashboard API and IoC block status

**Files:**
- Modify: `server-api/app/api/routes/web_protection.py` (append `router`)
- Modify: `server-api/app/main.py` (register `router`)
- Modify: `server-api/app/api/routes/iocs.py` (`blocked` for domain/url rows)
- Test: `tests/server-api/test_web_protection_api.int.py`, `tests/server-api/test_iocs_api.int.py` (append one test)

**Interfaces:**
- Consumes: Task 1 `normalize`, `DomainError`, `allow_match`; Task 2 `web_page.sanitize`, `PageError`, `document`, `SAMPLE`; Task 3 `web_blocks.*`.
- Produces (HTTP, used by Task 5):
  - `GET /api/web-blocks?q=&source=&status=active&limit=50&offset=0` → `{"total", "items": [Block]}`, Block = `{id, domain, group_id, source, status, reason, sample_url, alert_id, created_at, expires_at}`
  - `POST /api/web-blocks {value, reason, expires_at?, group_id?}` → 201 Block; 422 `{"detail": DomainError text}`; 409 `{"detail": "<domain> is allowlisted (<rule>)"}`
  - `DELETE /api/web-blocks/{id}` → `{"status": "removed" | "allowlisted"}`
  - `GET /api/web-allowlist` → `{"items": [{id, group_id, domain, include_subdomains, builtin, enabled}]}`; `POST /api/web-allowlist {domain, include_subdomains, group_id?}` → 201; `PATCH /api/web-allowlist/{id} {enabled?, include_subdomains?}`; `DELETE /api/web-allowlist/{id}` (409 for built-ins)
  - `GET /api/web-block-policies/{group_id}` → `{group_id, enabled, feed_enabled, alert_enabled, alert_block_days, max_entries, page_html, contact, custom_page}`; `PUT` same body minus `group_id`/`custom_page` (`page_html: null` resets to built-in); `POST /api/web-block-policies/{group_id}/preview {page_html?}` → `{"html": full document}`

- [ ] **Step 1: Write the failing tests** — `tests/server-api/test_web_protection_api.int.py`:

```python
# tests/server-api/test_web_protection_api.int.py
"""Web Protection dashboard API: manual block/unblock, allowlist, policy and
block page — every route scoped to the caller's group."""
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.api.routes import web_protection as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import WebAllowRule, WebBlockEntry
from app.services import web_blocks as wb

MANAGE = ("alerts:read", "agents:manage")


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


@pytest.fixture
async def env(evidence_api, monkeypatch):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    audits = []

    async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None, **kwargs):
        audits.append((action, resource_id))

    monkeypatch.setattr(routes, "audit_log", audit)
    evidence_api.user = evidence_api.make_user(perms=MANAGE)
    evidence_api.audit_calls = audits
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with evidence_api.sessions() as db:
        await wb.seed_builtin_allowlist(db)
    wb.invalidate()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def test_manual_block_normalises_and_audits(env):
    r = await env.api.post("/api/web-blocks", json={"value": "https://Evil.example/login", "reason": "phishing"})
    assert r.status_code == 201, r.text
    assert r.json()["domain"] == "evil.example" and r.json()["group_id"] == "blue" and r.json()["source"] == "manual"
    assert ("web_block.add", r.json()["id"]) in env.audit_calls


async def test_ip_and_allowlisted_values_are_refused(env):
    r = await env.api.post("/api/web-blocks", json={"value": "45.33.32.156"})
    assert r.status_code == 422 and "IP addresses cannot be web-blocked" in r.json()["detail"]
    r = await env.api.post("/api/web-blocks", json={"value": "raw.github.com"})
    assert r.status_code == 409 and "github.com" in r.json()["detail"]


async def test_unblock_and_reblock_reuse_the_entry(env):
    created = (await env.api.post("/api/web-blocks", json={"value": "evil.example"})).json()
    assert (await env.api.delete(f"/api/web-blocks/{created['id']}")).json() == {"status": "removed"}
    again = (await env.api.post("/api/web-blocks", json={"value": "evil.example"})).json()
    assert again["id"] == created["id"] and again["status"] == "active"


async def test_unblocking_a_feed_entry_allowlists_it_for_the_group(env):
    async with env.sessions() as db:
        entry = WebBlockEntry(domain="feed.example", group_id="*", source="urlhaus", reason="feed")
        db.add(entry)
        await db.commit()
    assert (await env.api.delete(f"/api/web-blocks/{entry.id}")).json() == {"status": "allowlisted"}
    items = (await env.api.get("/api/web-allowlist")).json()["items"]
    assert any(i["domain"] == "feed.example" and i["group_id"] == "blue" for i in items)
    async with env.sessions() as db:
        assert (await db.get(WebBlockEntry, entry.id)).status == "active"


async def test_groups_cannot_see_or_change_each_other(env):
    async with env.sessions() as db:
        red = WebBlockEntry(domain="red.example", group_id="red", source="manual")
        db.add(red)
        await db.commit()
    listed = (await env.api.get("/api/web-blocks")).json()["items"]
    assert all(i["group_id"] in ("blue", "*") for i in listed)
    assert (await env.api.delete(f"/api/web-blocks/{red.id}")).status_code == 404
    assert (await env.api.post("/api/web-blocks", json={"value": "x.example", "group_id": "red"})).status_code == 404
    assert (await env.api.get("/api/web-block-policies/red")).status_code == 404


async def test_changes_need_agents_manage(env):
    env.user = env.make_user(perms=("alerts:read",))
    assert (await env.api.post("/api/web-blocks", json={"value": "evil.example"})).status_code == 403
    assert (await env.api.get("/api/web-blocks")).status_code == 200


async def test_allowlist_crud_and_builtin_protection(env):
    r = await env.api.post("/api/web-allowlist", json={"domain": "Intranet.Example", "include_subdomains": True})
    assert r.status_code == 201 and r.json()["domain"] == "intranet.example"
    rule_id = r.json()["id"]
    assert (await env.api.patch(f"/api/web-allowlist/{rule_id}", json={"enabled": False})).json()["enabled"] is False
    assert (await env.api.delete(f"/api/web-allowlist/{rule_id}")).status_code == 200
    builtin = next(i for i in (await env.api.get("/api/web-allowlist")).json()["items"] if i["domain"] == "github.com")
    assert (await env.api.delete(f"/api/web-allowlist/{builtin['id']}")).status_code == 409
    assert (await env.api.patch(f"/api/web-allowlist/{builtin['id']}", json={"enabled": False})).status_code == 403
    env.user = env.make_user(role="superadmin")
    assert (await env.api.patch(f"/api/web-allowlist/{builtin['id']}", json={"enabled": False})).json()["enabled"] is False


async def test_allowlist_change_bumps_the_rules_marker(env):
    async with env.sessions() as db:
        before = await wb._rules_seq(db)
    await env.api.post("/api/web-allowlist", json={"domain": "intranet.example"})
    async with env.sessions() as db:
        assert await wb._rules_seq(db) > before


async def test_policy_defaults_save_sanitises_and_preview(env):
    policy = (await env.api.get("/api/web-block-policies/blue")).json()
    assert policy["enabled"] is False and policy["custom_page"] is False and "{{domain}}" in policy["page_html"]
    body = {"enabled": True, "feed_enabled": False, "alert_enabled": False, "alert_block_days": 14,
            "max_entries": 1000, "contact": "soc@corp.example",
            "page_html": "<h1>Blocked {{domain}}</h1><script>alert(1)</script>"}
    saved = (await env.api.put("/api/web-block-policies/blue", json=body)).json()
    assert saved["enabled"] is True and saved["custom_page"] is True and "<script" not in saved["page_html"]
    preview = (await env.api.post("/api/web-block-policies/blue/preview", json={"page_html": "<p>{{domain}}</p>"})).json()
    assert preview["html"].startswith("<!doctype html>") and "malicious.example" in preview["html"]
    reset = (await env.api.put("/api/web-block-policies/blue", json={**body, "page_html": None})).json()
    assert reset["custom_page"] is False
    bad = await env.api.put("/api/web-block-policies/blue", json={**body, "max_entries": 10})
    assert bad.status_code == 422
```

Append to `tests/server-api/test_iocs_api.int.py`:

```python
async def test_domain_rows_report_whether_the_group_blocks_them(iocs_api):
    from app.models.models import WebBlockEntry, WebBlockPolicy
    async with iocs_api.sessions() as db:
        db.add(WebBlockPolicy(group_id="blue", enabled=True))
        db.add(WebBlockEntry(domain="evil.example", group_id="blue", source="manual"))
        await db.commit()
    iocs_api.reply["value"] = {"aggregations": {"types": {"buckets": []}, "matched": {"count": {"value": 3}, "iocs": {"buckets": [
        {"key": k, "alerts": {"value": 1}, "hosts": {"value": 1}, "first_seen": {}, "last_seen": {}, "max_severity": {}}
        for k in ("domain:evil.example", "url:http://evil.example/a", "ip:45.33.32.156")]}}}}
    items = (await iocs_api.api.get("/api/iocs")).json()["items"]
    assert [i["blocked"] for i in items] == [True, True, None]
```

- [ ] **Step 2: Run to verify failure** — `$PY -m pytest tests/server-api/test_web_protection_api.int.py tests/server-api/test_iocs_api.int.py -q` → failures (`routes.router` missing; `blocked` is None).

- [ ] **Step 3: Implement**

Append to `server-api/app/api/routes/web_protection.py` (add the imports at the top of the file):

```python
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import Query, Response
from pydantic import Field
from sqlalchemy import func, or_, select

from app.core.deps import get_scoped_group, require_permission
from app.models.models import User, WebAllowRule, WebBlockEntry, WebBlockPolicy
from app.services import web_page
from app.services.audit import audit_log
from worker.web_domains import DomainError, allow_match, normalize

router = APIRouter(tags=["web-protection"])
Read = Depends(require_permission("alerts:read"))
Manage = Depends(require_permission("agents:manage"))


def _target_group(group_filter: Optional[str], requested: Optional[str]) -> str:
    """The group a change applies to: the caller's own, or any group for a superadmin."""
    if group_filter is not None:
        if requested and requested != group_filter:
            raise HTTPException(status_code=404, detail="Group not found")
        return group_filter
    return requested or "default"


def _visible(group_filter: Optional[str], column):
    return True if group_filter is None else column.in_((group_filter, web_blocks.FEED_GROUP))


def _block_out(r: WebBlockEntry) -> dict:
    return {"id": str(r.id), "domain": r.domain, "group_id": r.group_id, "source": r.source, "status": r.status,
            "reason": r.reason, "sample_url": r.sample_url, "alert_id": str(r.alert_id) if r.alert_id else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None}


def _rule_out(r: WebAllowRule) -> dict:
    return {"id": str(r.id), "group_id": r.group_id, "domain": r.domain,
            "include_subdomains": r.include_subdomains, "builtin": r.builtin, "enabled": r.enabled}


class BlockIn(BaseModel):
    value: str = Field(..., max_length=2048)
    reason: str = Field("", max_length=500)
    expires_at: Optional[datetime] = None
    group_id: Optional[str] = None


@router.get("/api/web-blocks")
async def list_blocks(
    q: str = Query("", max_length=253), source: str = "", status: str = "active",
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db), _=Read, group: Optional[str] = Depends(get_scoped_group),
):
    query = select(WebBlockEntry).where(_visible(group, WebBlockEntry.group_id))
    if q.strip():
        query = query.where(WebBlockEntry.domain.ilike(f"%{q.strip().lower()}%"))
    if source:
        query = query.where(WebBlockEntry.source == source)
    if status:
        query = query.where(WebBlockEntry.status == status)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(WebBlockEntry.updated_at.desc()).offset(offset).limit(limit))).scalars().all()
    return {"total": total, "items": [_block_out(r) for r in rows]}


@router.post("/api/web-blocks", status_code=201)
async def add_block(body: BlockIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                    group: Optional[str] = Depends(get_scoped_group)):
    target = _target_group(group, body.group_id)
    try:
        domain = normalize(body.value)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    rule = allow_match(domain, await web_blocks.allow_rules(db, target))
    if rule:
        raise HTTPException(status_code=409, detail=f"{domain} is allowlisted ({rule})")
    row = (await db.execute(select(WebBlockEntry).where(
        WebBlockEntry.group_id == target, WebBlockEntry.domain == domain, WebBlockEntry.source == "manual"))).scalar_one_or_none()
    if row is None:
        row = WebBlockEntry(domain=domain, group_id=target, source="manual", created_by=user.id)
        db.add(row)
    row.status, row.reason, row.expires_at, row.seq = "active", body.reason.strip(), body.expires_at, web_blocks.next_seq()
    await db.commit()
    await db.refresh(row)
    web_blocks.invalidate()
    await audit_log(db, user.id, "web_block.add", "web_block", str(row.id), {"domain": domain, "group_id": target})
    return _block_out(row)


@router.delete("/api/web-blocks/{entry_id}")
async def remove_block(entry_id: UUID, db: AsyncSession = Depends(get_db), user: User = Manage,
                       group: Optional[str] = Depends(get_scoped_group)):
    row = await db.get(WebBlockEntry, entry_id)
    if row is None or (group is not None and row.group_id not in (group, web_blocks.FEED_GROUP)):
        raise HTTPException(status_code=404, detail="Block not found")
    if row.group_id == web_blocks.FEED_GROUP and group is not None:
        # a feed entry is shared: allowlist it for this group so the next feed sync cannot re-block it
        exists = (await db.execute(select(WebAllowRule).where(
            WebAllowRule.group_id == group, WebAllowRule.domain == row.domain))).scalar_one_or_none()
        if exists is None:
            db.add(WebAllowRule(group_id=group, domain=row.domain, created_by=user.id))
        elif not exists.enabled:
            exists.enabled = True
        await web_blocks.mark_rules_changed(db)
        await db.commit()
        await audit_log(db, user.id, "web_block.allowlist_feed", "web_block", str(row.id), {"domain": row.domain, "group_id": group})
        return {"status": "allowlisted"}
    row.status, row.seq = "removed", web_blocks.next_seq()
    await db.commit()
    web_blocks.invalidate()
    await audit_log(db, user.id, "web_block.remove", "web_block", str(row.id), {"domain": row.domain})
    return {"status": "removed"}


class RuleIn(BaseModel):
    domain: str = Field(..., max_length=2048)
    include_subdomains: bool = False
    group_id: Optional[str] = None


class RulePatch(BaseModel):
    enabled: Optional[bool] = None
    include_subdomains: Optional[bool] = None


@router.get("/api/web-allowlist")
async def list_rules(db: AsyncSession = Depends(get_db), _=Read, group: Optional[str] = Depends(get_scoped_group)):
    rows = (await db.execute(select(WebAllowRule).where(_visible(group, WebAllowRule.group_id))
                             .order_by(WebAllowRule.builtin, WebAllowRule.domain))).scalars().all()
    return {"items": [_rule_out(r) for r in rows]}


@router.post("/api/web-allowlist", status_code=201)
async def add_rule(body: RuleIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                   group: Optional[str] = Depends(get_scoped_group)):
    target = _target_group(group, body.group_id)
    try:
        domain = normalize(body.domain)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    row = (await db.execute(select(WebAllowRule).where(
        WebAllowRule.group_id == target, WebAllowRule.domain == domain))).scalar_one_or_none()
    if row is None:
        row = WebAllowRule(group_id=target, domain=domain, created_by=user.id)
        db.add(row)
    row.include_subdomains, row.enabled = body.include_subdomains, True
    await web_blocks.mark_rules_changed(db)
    await db.commit()
    await db.refresh(row)
    await audit_log(db, user.id, "web_allowlist.add", "web_allowlist", str(row.id), {"domain": domain, "group_id": target})
    return _rule_out(row)


async def _own_rule(db, rule_id: UUID, group: Optional[str]) -> WebAllowRule:
    row = await db.get(WebAllowRule, rule_id)
    if row is None or (group is not None and row.group_id not in (group, web_blocks.FEED_GROUP)):
        raise HTTPException(status_code=404, detail="Rule not found")
    if group is not None and row.group_id == web_blocks.FEED_GROUP:
        raise HTTPException(status_code=403, detail="Only a superadmin can change rules for every group")
    return row


@router.patch("/api/web-allowlist/{rule_id}")
async def update_rule(rule_id: UUID, body: RulePatch, db: AsyncSession = Depends(get_db), user: User = Manage,
                      group: Optional[str] = Depends(get_scoped_group)):
    row = await _own_rule(db, rule_id, group)
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.include_subdomains is not None:
        row.include_subdomains = body.include_subdomains
    await web_blocks.mark_rules_changed(db)
    await db.commit()
    await audit_log(db, user.id, "web_allowlist.update", "web_allowlist", str(row.id), body.model_dump(exclude_none=True))
    return _rule_out(row)


@router.delete("/api/web-allowlist/{rule_id}")
async def delete_rule(rule_id: UUID, db: AsyncSession = Depends(get_db), user: User = Manage,
                      group: Optional[str] = Depends(get_scoped_group)):
    row = await _own_rule(db, rule_id, group)
    if row.builtin:
        raise HTTPException(status_code=409, detail="Built-in rules can be disabled, not deleted")
    await db.delete(row)
    await web_blocks.mark_rules_changed(db)
    await db.commit()
    await audit_log(db, user.id, "web_allowlist.delete", "web_allowlist", str(rule_id), {"domain": row.domain})
    return {"status": "deleted"}


class PolicyIn(BaseModel):
    enabled: bool
    feed_enabled: bool = False
    alert_enabled: bool = False
    alert_block_days: int = Field(30, ge=1, le=365)
    max_entries: int = Field(50000, ge=100, le=200000)
    page_html: Optional[str] = None
    contact: str = Field("", max_length=255)


class PreviewIn(BaseModel):
    page_html: Optional[str] = None


def _policy_group(group_filter: Optional[str], group_id: str) -> str:
    if group_filter is not None and group_id != group_filter:
        raise HTTPException(status_code=404, detail="Group not found")
    return group_id


@router.get("/api/web-block-policies/{group_id}")
async def get_policy(group_id: str, db: AsyncSession = Depends(get_db), _=Read,
                     group: Optional[str] = Depends(get_scoped_group)):
    target = _policy_group(group, group_id)
    policy = await web_blocks.policy_for(db, target)
    return {"group_id": target, **{k: v for k, v in policy.items() if k != "seq"}}


@router.put("/api/web-block-policies/{group_id}")
async def put_policy(group_id: str, body: PolicyIn, db: AsyncSession = Depends(get_db), user: User = Manage,
                     group: Optional[str] = Depends(get_scoped_group)):
    target = _policy_group(group, group_id)
    try:
        page = web_page.sanitize(body.page_html) if body.page_html is not None else None
    except web_page.PageError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    row = await db.get(WebBlockPolicy, target) or WebBlockPolicy(group_id=target)
    for key in ("enabled", "feed_enabled", "alert_enabled", "alert_block_days", "max_entries", "contact"):
        setattr(row, key, getattr(body, key))
    row.page_html, row.seq = page, web_blocks.next_seq()
    db.add(row)
    await db.commit()
    web_blocks.invalidate()
    await audit_log(db, user.id, "web_block_policy.update", "web_block_policy", target,
                    body.model_dump(exclude={"page_html"}) | {"custom_page": page is not None})
    policy = await web_blocks.policy_for(db, target)
    return {"group_id": target, **{k: v for k, v in policy.items() if k != "seq"}}


@router.post("/api/web-block-policies/{group_id}/preview")
async def preview_page(group_id: str, body: PreviewIn, db: AsyncSession = Depends(get_db), _=Read,
                       group: Optional[str] = Depends(get_scoped_group)):
    target = _policy_group(group, group_id)
    policy = await web_blocks.policy_for(db, target)
    try:
        page = web_page.sanitize(body.page_html) if body.page_html is not None else policy["page_html"]
    except web_page.PageError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    values = {**web_page.SAMPLE, "contact": policy["contact"] or web_page.SAMPLE["contact"]}
    return {"html": web_page.document(page, values)}
```

Register in `server-api/app/main.py`: change the Task 3 import to `from app.api.routes.web_protection import router as web_protection_router, agent_router as web_protection_agent_router` and add `web_protection_router,` to the router list.

In `server-api/app/api/routes/iocs.py` `list_iocs`: add `db: AsyncSession = Depends(get_db)` to the signature; after building `items`, fill `blocked`:

```python
    from urllib.parse import urlsplit
    from app.services import web_blocks
    from worker.web_domains import DomainError, normalize

    def _host(item: dict) -> Optional[str]:
        try:
            return normalize(item["value"] if item["type"] == "domain" else (urlsplit(item["value"]).hostname or ""))
        except (DomainError, ValueError):
            return None

    hosts = {id(i): _host(i) for i in items if i["type"] in ("domain", "url")}
    blocked = await web_blocks.blocked_domains(db, group, [h for h in hosts.values() if h])
    for item in items:
        if id(item) in hosts:
            item["blocked"] = hosts[id(item)] in blocked if hosts[id(item)] else False
```

(move the imports to the top of `iocs.py`; remove the `# Web Protection (stage B1) fills this` comment).

- [ ] **Step 4: Verify** — `$PY -m pytest tests/server-api/test_web_protection_api.int.py tests/server-api/test_iocs_api.int.py tests/server-api/test_web_blocks.int.py -q` → all pass; then `$PY -m pytest tests/server-api -q -p no:cacheprovider` (full suite, CI versions) → green.

- [ ] **Step 5: Commit** — `feat(webblock): web protection API and IoC block status`.

---

### Task 5: Web Protection dashboard page and Block web action

**Files:**
- Create: `dashboard/src/hooks/useWebProtection.ts`, `dashboard/src/pages/WebProtectionPage.tsx`
- Modify: `dashboard/src/pages/ThreatIocsPage.tsx`, `dashboard/src/App.tsx`, `dashboard/src/components/AppSidebar.tsx`

**Interfaces:**
- Consumes: Task 4 HTTP API; `useAuthStore` (`dashboard/src/stores/auth.ts`, user has `role`, `group_id`).
- Produces: route `/web-protection`; exports `useBlockWeb()` used by `ThreatIocsPage`.

- [ ] **Step 1: Hooks** — `dashboard/src/hooks/useWebProtection.ts`:

```ts
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface WebBlock {
  id: string
  domain: string
  group_id: string
  source: 'manual' | 'alert' | 'urlhaus' | 'phishtank'
  status: 'active' | 'removed' | 'suppressed'
  reason: string
  sample_url: string | null
  alert_id: string | null
  created_at: string | null
  expires_at: string | null
}

export interface AllowRule {
  id: string
  group_id: string
  domain: string
  include_subdomains: boolean
  builtin: boolean
  enabled: boolean
}

export interface WebPolicy {
  group_id: string
  enabled: boolean
  feed_enabled: boolean
  alert_enabled: boolean
  alert_block_days: number
  max_entries: number
  page_html: string
  contact: string
  custom_page: boolean
}

export interface BlockFilter { q: string; source: string; status: string; offset: number }
export const BLOCK_PAGE = 50
const KEY = ['web-protection']

export function apiError(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(d => (d as { msg?: string }).msg ?? String(d)).join('; ')
  return fallback
}

export function useWebBlocks(f: BlockFilter) {
  return useQuery<{ total: number; items: WebBlock[] }>({
    queryKey: [...KEY, 'blocks', f],
    queryFn: () => api.get('/api/web-blocks', {
      params: { q: f.q || undefined, source: f.source || undefined, status: f.status, limit: BLOCK_PAGE, offset: f.offset },
    }).then(r => r.data),
    placeholderData: keepPreviousData,
  })
}

export function useBlockWeb() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { value: string; reason?: string; expires_at?: string | null }) =>
      api.post('/api/web-blocks', body).then(r => r.data as WebBlock),
    onSuccess: () => { qc.invalidateQueries({ queryKey: KEY }); qc.invalidateQueries({ queryKey: ['iocs'] }) },
  })
}

export function useUnblockWeb() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/web-blocks/${id}`).then(r => r.data as { status: string }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: KEY }); qc.invalidateQueries({ queryKey: ['iocs'] }) },
  })
}

export function useAllowlist() {
  return useQuery<{ items: AllowRule[] }>({
    queryKey: [...KEY, 'allowlist'],
    queryFn: () => api.get('/api/web-allowlist').then(r => r.data),
  })
}

export function useAddAllowRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { domain: string; include_subdomains: boolean }) =>
      api.post('/api/web-allowlist', body).then(r => r.data as AllowRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useUpdateAllowRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; enabled?: boolean; include_subdomains?: boolean }) =>
      api.patch(`/api/web-allowlist/${id}`, body).then(r => r.data as AllowRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useDeleteAllowRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/web-allowlist/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useWebPolicy(group: string) {
  return useQuery<WebPolicy>({
    queryKey: [...KEY, 'policy', group],
    queryFn: () => api.get(`/api/web-block-policies/${encodeURIComponent(group)}`).then(r => r.data),
    enabled: !!group,
  })
}

export function useSaveWebPolicy(group: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Omit<WebPolicy, 'group_id' | 'custom_page' | 'page_html'> & { page_html: string | null }) =>
      api.put(`/api/web-block-policies/${encodeURIComponent(group)}`, body).then(r => r.data as WebPolicy),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function usePreviewPage(group: string) {
  return useMutation({
    mutationFn: (page_html: string | null) =>
      api.post(`/api/web-block-policies/${encodeURIComponent(group)}/preview`, { page_html })
        .then(r => (r.data as { html: string }).html),
  })
}
```

- [ ] **Step 2: Page** — `dashboard/src/pages/WebProtectionPage.tsx`:

```tsx
import { useEffect, useState } from 'react'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import {
  BLOCK_PAGE, type BlockFilter, type WebPolicy, apiError, useAddAllowRule, useAllowlist, useBlockWeb,
  useDeleteAllowRule, usePreviewPage, useSaveWebPolicy, useUnblockWeb, useUpdateAllowRule, useWebBlocks, useWebPolicy,
} from '@/hooks/useWebProtection'

type Tab = 'blocklist' | 'allowlist' | 'page'
const SOURCE_LABEL: Record<string, string> = { manual: 'Manual', alert: 'Alert', urlhaus: 'URLhaus', phishtank: 'PhishTank' }
const input = 'bg-muted border border-border rounded px-2 py-1.5 text-sm'
const button = 'text-xs px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-40 disabled:cursor-not-allowed'

function PolicySwitch({ group }: { group: string }) {
  const { data: policy, isError } = useWebPolicy(group)
  const save = useSaveWebPolicy(group)
  if (isError) return <p className="text-sm text-destructive">Could not load the policy.</p>
  if (!policy) return <Loader2 size={14} className="animate-spin" />
  const toggle = () => save.mutate({ ...policy, enabled: !policy.enabled, page_html: policy.custom_page ? policy.page_html : null })
  return (
    <div className="rounded-lg border border-border p-4 flex flex-wrap items-center gap-3">
      <div className="min-w-0">
        <div className="text-sm font-semibold">Web Protection for group {group}: {policy.enabled ? 'on' : 'off'}</div>
        <div className="text-xs text-muted-foreground">
          When on, agents redirect blocked domains to the block page. Agents also install a local certificate authority so the page shows on HTTPS sites.
        </div>
      </div>
      <button onClick={toggle} disabled={save.isPending}
        className={`ml-auto px-3 py-1.5 rounded text-sm font-medium ${policy.enabled ? 'border border-border hover:bg-muted' : 'bg-primary text-primary-foreground'}`}>
        {policy.enabled ? 'Turn off' : 'Turn on'}
      </button>
      {save.isError && <p className="w-full text-xs text-destructive">{apiError(save.error, 'Could not save.')}</p>}
    </div>
  )
}

function Blocklist({ group }: { group: string }) {
  const [filter, setFilter] = useState<BlockFilter>({ q: '', source: '', status: 'active', offset: 0 })
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const { data, isLoading, isError } = useWebBlocks(filter)
  const block = useBlockWeb()
  const unblock = useUnblockWeb()
  const update = (patch: Partial<BlockFilter>) => setFilter(f => ({ ...f, offset: 0, ...patch }))
  const submit = () => block.mutate({ value: value.trim(), reason: reason.trim() }, { onSuccess: () => { setValue(''); setReason('') } })

  return (
    <div className="space-y-3">
      <PolicySwitch group={group} />
      <form onSubmit={e => { e.preventDefault(); submit() }} className="flex flex-wrap items-end gap-2">
        <label className="space-y-1">
          <span className="block text-xs text-muted-foreground">Domain or URL</span>
          <input value={value} onChange={e => setValue(e.target.value)} placeholder="malicious.example"
            className={`${input} w-64 max-w-full font-mono`} />
        </label>
        <label className="space-y-1">
          <span className="block text-xs text-muted-foreground">Reason</span>
          <input value={reason} onChange={e => setReason(e.target.value)} className={`${input} w-64 max-w-full`} />
        </label>
        <button type="submit" disabled={!value.trim() || block.isPending}
          className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium inline-flex items-center gap-1 disabled:opacity-50">
          <Plus size={14} /> Block
        </button>
      </form>
      {block.isError && <p className="text-xs text-destructive">{apiError(block.error, 'Could not block.')}</p>}

      <div className="flex flex-wrap items-center gap-2">
        <input value={filter.q} onChange={e => update({ q: e.target.value })} placeholder="Search domain"
          aria-label="Search domain" className={`${input} w-56 max-w-full`} />
        <select value={filter.source} onChange={e => update({ source: e.target.value })} aria-label="Source" className={input}>
          <option value="">Any source</option>
          {Object.entries(SOURCE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select value={filter.status} onChange={e => update({ status: e.target.value })} aria-label="Status" className={input}>
          <option value="active">Blocked</option>
          <option value="removed">Unblocked</option>
          <option value="suppressed">Allowlisted</option>
        </select>
        <span className="text-xs text-muted-foreground ml-auto">{data ? `${data.total.toLocaleString()} domains` : ''}</span>
      </div>

      {isError ? <p className="text-sm text-destructive">Could not load the blocklist.</p>
        : isLoading ? <Loader2 size={16} className="animate-spin" />
        : !data?.items.length ? <p className="text-sm text-muted-foreground">No domains here.</p> : (
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                <tr>
                  <th className="text-left px-3 py-2">Domain</th>
                  <th className="text-left px-3 py-2">Source</th>
                  <th className="text-left px-3 py-2">Reason</th>
                  <th className="text-left px-3 py-2">Expires</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {data.items.map(b => (
                  <tr key={b.id} className="border-t border-border">
                    <td className="px-3 py-2 font-mono text-xs break-all">{b.domain}
                      {b.group_id === '*' && <span className="ml-1 text-muted-foreground">(all groups)</span>}</td>
                    <td className="px-3 py-2 text-xs">{SOURCE_LABEL[b.source] ?? b.source}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{b.reason || '—'}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{b.expires_at ? new Date(b.expires_at).toLocaleString() : 'never'}</td>
                    <td className="px-3 py-2 text-right">
                      {b.status === 'active' && (
                        <button className={button} disabled={unblock.isPending} onClick={() => unblock.mutate(b.id)}>
                          {b.group_id === '*' ? 'Allow for my group' : 'Unblock'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      {unblock.isError && <p className="text-xs text-destructive">{apiError(unblock.error, 'Could not unblock.')}</p>}
      {data && data.total > BLOCK_PAGE && (
        <div className="flex items-center gap-2 text-xs">
          <button className={button} disabled={filter.offset === 0}
            onClick={() => setFilter(f => ({ ...f, offset: Math.max(0, f.offset - BLOCK_PAGE) }))}>Previous</button>
          <span className="text-muted-foreground">{filter.offset + 1}–{Math.min(filter.offset + BLOCK_PAGE, data.total)} of {data.total}</span>
          <button className={button} disabled={filter.offset + BLOCK_PAGE >= data.total}
            onClick={() => setFilter(f => ({ ...f, offset: f.offset + BLOCK_PAGE }))}>Next</button>
        </div>
      )}
    </div>
  )
}

function Allowlist({ superadmin }: { superadmin: boolean }) {
  const { data, isLoading, isError } = useAllowlist()
  const add = useAddAllowRule()
  const updateRule = useUpdateAllowRule()
  const remove = useDeleteAllowRule()
  const [domain, setDomain] = useState('')
  const [subdomains, setSubdomains] = useState(true)
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">Domains on this list are never blocked, even when a feed or an alert lists them.</p>
      <form onSubmit={e => { e.preventDefault(); add.mutate({ domain: domain.trim(), include_subdomains: subdomains }, { onSuccess: () => setDomain('') }) }}
        className="flex flex-wrap items-center gap-2">
        <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="intranet.example" aria-label="Domain to allow"
          className={`${input} w-64 max-w-full font-mono`} />
        <label className="text-xs inline-flex items-center gap-1">
          <input type="checkbox" checked={subdomains} onChange={e => setSubdomains(e.target.checked)} /> Include subdomains
        </label>
        <button type="submit" disabled={!domain.trim() || add.isPending} className={button}>Allow</button>
      </form>
      {(add.isError || updateRule.isError || remove.isError) && (
        <p className="text-xs text-destructive">{apiError(add.error ?? updateRule.error ?? remove.error, 'Could not save.')}</p>
      )}
      {isError ? <p className="text-sm text-destructive">Could not load the allowlist.</p>
        : isLoading ? <Loader2 size={16} className="animate-spin" /> : (
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                <tr><th className="text-left px-3 py-2">Domain</th><th className="text-left px-3 py-2">Scope</th><th className="px-3 py-2" /></tr>
              </thead>
              <tbody>
                {data?.items.map(r => {
                  const editable = r.group_id !== '*' || superadmin
                  return (
                    <tr key={r.id} className={`border-t border-border ${r.enabled ? '' : 'opacity-60'}`}>
                      <td className="px-3 py-2 font-mono text-xs">{r.domain}{r.include_subdomains ? ' + subdomains' : ''}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{r.builtin ? 'Built-in' : r.group_id === '*' ? 'All groups' : 'This group'}</td>
                      <td className="px-3 py-2 text-right space-x-1 whitespace-nowrap">
                        {editable && (
                          <button className={button} disabled={updateRule.isPending}
                            onClick={() => updateRule.mutate({ id: r.id, enabled: !r.enabled })}>{r.enabled ? 'Disable' : 'Enable'}</button>
                        )}
                        {editable && !r.builtin && (
                          <button className={button} aria-label={`Delete ${r.domain}`} disabled={remove.isPending}
                            onClick={() => remove.mutate(r.id)}><Trash2 size={12} /></button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
    </div>
  )
}

function BlockPageEditor({ group }: { group: string }) {
  const { data: policy, isError } = useWebPolicy(group)
  const save = useSaveWebPolicy(group)
  const preview = usePreviewPage(group)
  const [html, setHtml] = useState('')
  const [contact, setContact] = useState('')
  useEffect(() => {
    if (policy) { setHtml(policy.page_html); setContact(policy.contact) }
  }, [policy])
  if (isError) return <p className="text-sm text-destructive">Could not load the policy.</p>
  if (!policy) return <Loader2 size={16} className="animate-spin" />
  const body = (page: string | null): Omit<WebPolicy, 'group_id' | 'custom_page' | 'page_html'> & { page_html: string | null } =>
    ({ enabled: policy.enabled, feed_enabled: policy.feed_enabled, alert_enabled: policy.alert_enabled,
       alert_block_days: policy.alert_block_days, max_entries: policy.max_entries, contact, page_html: page })
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-2 min-w-0">
        <p className="text-xs text-muted-foreground">
          HTML and CSS only. Scripts, forms and external images are removed when you save. Variables: {'{{domain}} {{reason}} {{source}} {{time}} {{hostname}} {{contact}}'}.
        </p>
        <textarea value={html} onChange={e => setHtml(e.target.value)} rows={18} aria-label="Block page HTML"
          className="w-full bg-muted border border-border rounded px-3 py-2 text-xs font-mono" />
        <label className="block space-y-1">
          <span className="text-xs text-muted-foreground">Contact shown as {'{{contact}}'}</span>
          <input value={contact} onChange={e => setContact(e.target.value)} className={`${input} w-full`} />
        </label>
        <div className="flex flex-wrap gap-2">
          <button className={button} disabled={preview.isPending} onClick={() => preview.mutate(html)}>Preview</button>
          <button className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
            disabled={save.isPending} onClick={() => save.mutate(body(html))}>Save</button>
          <button className={button} disabled={save.isPending || !policy.custom_page} onClick={() => save.mutate(body(null))}>Reset to built-in</button>
        </div>
        {save.isError && <p className="text-xs text-destructive">{apiError(save.error, 'Could not save.')}</p>}
        {preview.isError && <p className="text-xs text-destructive">{apiError(preview.error, 'Could not render the preview.')}</p>}
      </div>
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground mb-1">Preview with sample values</div>
        <iframe title="Block page preview" sandbox="" srcDoc={preview.data ?? ''}
          className="w-full h-96 rounded border border-border bg-white" />
      </div>
    </div>
  )
}

export default function WebProtectionPage() {
  const user = useAuthStore(s => s.user)
  const superadmin = user?.role === 'superadmin'
  const [group, setGroup] = useState(superadmin ? 'default' : user?.group_id ?? 'default')
  const [tab, setTab] = useState<Tab>('blocklist')
  return (
    <div className="p-6 space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <h1 className="text-xl font-bold">Web Protection</h1>
          <p className="text-sm text-muted-foreground">Block domains on your endpoints and choose the page users see.</p>
        </div>
        {superadmin && (
          <label className="ml-auto text-xs space-y-1">
            <span className="block text-muted-foreground">Group</span>
            <input value={group} onChange={e => setGroup(e.target.value.trim())} className={`${input} w-40`} />
          </label>
        )}
      </div>
      <div className="flex flex-wrap gap-1 border-b border-border">
        {([['blocklist', 'Blocklist'], ['allowlist', 'Allowlist'], ['page', 'Block page']] as const).map(([key, label]) => (
          <button key={key} aria-pressed={tab === key} onClick={() => setTab(key)}
            className={`px-3 py-1.5 text-sm border-b-2 -mb-px ${tab === key ? 'border-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            {label}
          </button>
        ))}
      </div>
      {tab === 'blocklist' && <Blocklist group={group} />}
      {tab === 'allowlist' && <Allowlist superadmin={superadmin} />}
      {tab === 'page' && <BlockPageEditor key={group} group={group} />}
    </div>
  )
}
```

If `useAuthStore`'s selector shape differs (check `dashboard/src/stores/auth.ts`), read `user` the way other pages do and note it in the report. A superadmin's blocklist and allowlist lists show every group; the Group field only scopes the policy and the block page.

- [ ] **Step 3: Threat IoCs integration** — in `dashboard/src/pages/ThreatIocsPage.tsx`:
  - import `{ apiError, useBlockWeb } from '@/hooks/useWebProtection'` and `Ban` from `lucide-react`;
  - in `Detail`, add `const block = useBlockWeb()` and, for `ioc.type === 'domain' || ioc.type === 'url'`, a button after Hunt:

```tsx
        {(ioc.type === 'domain' || ioc.type === 'url') && (
          ioc.blocked ? <span className="text-xs px-2 py-1 rounded border border-border text-muted-foreground">Blocked on endpoints</span> : (
            <button disabled={block.isPending || block.isSuccess}
              onClick={() => block.mutate({ value: ioc.value, reason: `Threat IoC seen in ${ioc.alerts} alert(s)` })}
              className="text-xs px-2 py-1 rounded border border-border hover:bg-muted inline-flex items-center gap-1 disabled:opacity-40">
              <Ban size={12} /> {block.isSuccess ? 'Blocked' : 'Block web'}
            </button>
          )
        )}
```

    and below the existing mutation errors: `{block.isError && <p className="text-xs text-destructive">{apiError(block.error, 'Could not block.')}</p>}`;
  - add a "Status" column after "Severity" in the table: header `<th className="text-left px-3 py-2">Status</th>`, cell `<td className="px-3 py-2 text-xs">{ioc.blocked ? 'Blocked' : ioc.blocked === false ? 'Not blocked' : '—'}</td>`.

- [ ] **Step 4: Route and menu** — `App.tsx`: `import WebProtectionPage from '@/pages/WebProtectionPage'` and `<Route path="/web-protection" element={<WebProtectionPage />} />` next to `/threat-iocs`. `AppSidebar.tsx`: add `Globe` to the lucide import and `{ to: '/web-protection', label: 'Web Protection', icon: Globe, minRole: 'analyst' },` in the Environment group after `Malware hashes`.

- [ ] **Step 5: Verify** — `cd dashboard && npx tsc --noEmit -p . && npx vite build` → exit 0. Browser check only if a dev stack is reachable.

- [ ] **Step 6: Commit** — `feat(dashboard): Web Protection page and Block web action`.

---

## Final verification

```bash
$PY -m pytest tests/server-api tests/evidence -q -p no:cacheprovider
$PY -m pytest tests/worker worker/tests -q --ignore=tests/worker/test_pipeline.int.test.py \
  --deselect worker/tests/test_rag.py::test_embed_text_returns_384_dimensions \
  --deselect worker/tests/test_rag.py::test_embed_text_different_inputs_differ
cd dashboard && npx tsc --noEmit -p . && npx vite build
```
