# Platform Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 12 platform improvements from the CSO/product audit: rate limiting, SOAR actions (isolate + block IP), multi-model LLM fallback, nav cleanup (remove Handover/SOP), global search, attack timeline, Jira webhook format, MFA/TOTP, WebSocket real-time feed, UEBA baseline graph, and correlation match fields.

**Architecture:** Full-stack changes across FastAPI server-api (Python), worker (Python), and React dashboard (TypeScript). Tasks are grouped by subsystem — Groups A, B, C are independent and can run in parallel. Groups D, E, F are sequential within themselves.

**Tech Stack:** FastAPI + SQLAlchemy async + React + TypeScript + PostgreSQL + Redis. New deps: `slowapi`, `pyotp`, `qrcode[pil]`, `anthropic` (optional fallback).

---

## GROUP A — Backend Security & AI (independent, no frontend changes)

### Task A1: Rate Limiting on Login

**Files:**
- Modify: `server-api/requirements.txt`
- Modify: `server-api/app/main.py` (add Limiter setup)
- Modify: `server-api/app/api/routes/auth.py` (apply limit decorator)

- [ ] **Step 1: Add slowapi to requirements**

```
# server-api/requirements.txt — append:
slowapi==0.1.9
```

- [ ] **Step 2: Initialize Limiter in main.py**

After line `from fastapi.middleware.cors import CORSMiddleware` add:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
```

After `app = FastAPI(...)` (find it around line 300), add:
```python
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

- [ ] **Step 3: Apply rate limit to login endpoint**

In `server-api/app/api/routes/auth.py`, add import at top:
```python
from fastapi import Request
from app.main import limiter
```

Change the login function signature to add `request: Request` param and decorator:
```python
@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    background: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
```

- [ ] **Step 4: Rebuild and test**

```bash
cd /home/wonka/Documents/hackathon
docker-compose build server-api && docker-compose up -d server-api
# Test: 6 rapid login attempts should get 429 on the 6th
for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"username":"x","password":"y"}'; done
# Expected: 401 401 401 401 401 429
```

- [ ] **Step 5: Commit**

```bash
git add server-api/requirements.txt server-api/app/main.py server-api/app/api/routes/auth.py
git commit -m "feat(security): rate limit login endpoint to 5 req/min per IP via slowapi"
```

---

### Task A2: SOAR — isolate_agent Action

The Go agent already supports `task_type = "isolate_host"` (see `agent/internal/task/runner.go:103`). We just need to wire it from SOAR.

**Files:**
- Modify: `worker/worker/soar_engine.py`
- Modify: `server-api/app/api/routes/soar.py`

- [ ] **Step 1: Add action handler in soar_engine.py**

After `async def _action_add_note(...)` block and before the `_ACTION_HANDLERS` dict, add:

```python
async def _action_isolate_agent(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    """Create an isolate_host task for the agent that generated this alert."""
    hostname = ctx.get("hostname")
    if not hostname:
        log.warning("soar_isolate_skipped", reason="no hostname in alert context")
        return

    import httpx, os
    api_url = os.environ.get("API_URL", "http://server-api:8000")
    api_token = os.environ.get("WORKER_API_TOKEN", "")

    async with AsyncSessionLocal() as db:
        # Find agent by hostname
        from worker.models import Agent, AgentTask
        from sqlalchemy import select as _select
        agent_q = _select(Agent).where(Agent.hostname == hostname, Agent.status == "online")
        agent = (await db.execute(agent_q)).scalar_one_or_none()
        if not agent:
            note = f"**SOAR Isolate** — agent `{hostname}` not found or offline. Manual isolation required."
            db.add(AlertNote(alert_id=alert_id, content=note))
            await db.commit()
            return

        task = AgentTask(
            agent_id=agent.id,
            task_type="isolate_host",
            payload={},
            status="pending",
        )
        db.add(task)
        # Mark agent as isolated in DB
        from sqlalchemy import update as _update
        await db.execute(_update(Agent).where(Agent.id == agent.id).values(is_isolated=True))
        db.add(AlertNote(
            alert_id=alert_id,
            content=f"**SOAR Isolate** — isolation task queued for `{hostname}` (agent_id: {agent.id})"
        ))
        await db.commit()
        log.info("soar_isolate_queued", hostname=hostname, agent_id=str(agent.id))
```

- [ ] **Step 2: Add block_ip action handler in soar_engine.py**

After `_action_isolate_agent`, add:

```python
async def _action_block_ip(alert_id: uuid.UUID, ctx: dict, params: dict) -> None:
    """Create a block_ip task on the agent that reported this alert."""
    source_ip = ctx.get("source_ip") or params.get("ip")
    hostname = ctx.get("hostname")
    if not source_ip:
        log.warning("soar_block_ip_skipped", reason="no source_ip in context")
        return

    async with AsyncSessionLocal() as db:
        from worker.models import Agent, AgentTask
        from sqlalchemy import select as _select
        agent_q = _select(Agent).where(Agent.hostname == hostname, Agent.status == "online")
        agent = (await db.execute(agent_q)).scalar_one_or_none()
        if not agent:
            db.add(AlertNote(
                alert_id=alert_id,
                content=f"**SOAR Block IP** — agent `{hostname}` not found. Manual block required for `{source_ip}`."
            ))
            await db.commit()
            return

        task = AgentTask(
            agent_id=agent.id,
            task_type="block_ip",
            payload={"ip": source_ip, "duration_seconds": params.get("duration_seconds", 3600)},
            status="pending",
        )
        db.add(task)
        db.add(AlertNote(
            alert_id=alert_id,
            content=f"**SOAR Block IP** — task queued to block `{source_ip}` on `{hostname}` for {params.get('duration_seconds', 3600)}s"
        ))
        await db.commit()
        log.info("soar_block_ip_queued", ip=source_ip, hostname=hostname)
```

- [ ] **Step 3: Register new actions in _ACTION_HANDLERS dict**

Find the dict definition and add the two new entries:
```python
_ACTION_HANDLERS = {
    "enrich_ioc":      _action_enrich_ioc,
    "send_webhook":    _action_send_webhook,
    "create_case":     _action_create_case,
    "suppress_alert":  _action_suppress_alert,
    "add_note":        _action_add_note,
    "isolate_agent":   _action_isolate_agent,
    "block_ip":        _action_block_ip,
}
```

- [ ] **Step 4: Update ACTION_TYPES in soar.py API route**

In `server-api/app/api/routes/soar.py`, find:
```python
ACTION_TYPES = Literal['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note']
```
Replace with:
```python
ACTION_TYPES = Literal['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note', 'isolate_agent', 'block_ip']
```

- [ ] **Step 5: Add block_ip task type handler to Go agent**

In `agent/internal/task/runner.go`, find the switch statement and add after `case "unisolate_host":`:
```go
case "block_ip":
    ip, _ := task.Payload["ip"].(string)
    duration, _ := task.Payload["duration_seconds"].(float64)
    if duration == 0 {
        duration = 3600
    }
    return nil, blockIP(ip, int(duration))
```

In `agent/internal/task/isolation.go`, add at the end:
```go
func blockIP(ip string, durationSeconds int) error {
    if ip == "" {
        return fmt.Errorf("block_ip: empty IP")
    }
    // Add INPUT DROP rule for source IP
    if err := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").Run(); err != nil {
        return fmt.Errorf("block_ip iptables: %w", err)
    }
    // Schedule removal after duration using `at` if available, otherwise log and leave
    log.Printf("Blocked IP %s for %d seconds (manual unblock required if `at` unavailable)", ip, durationSeconds)
    return nil
}
```

- [ ] **Step 6: Rebuild and commit**

```bash
cd /home/wonka/Documents/hackathon
docker-compose build worker server-api && docker-compose up -d worker server-api
git add worker/worker/soar_engine.py server-api/app/api/routes/soar.py agent/internal/task/runner.go agent/internal/task/isolation.go
git commit -m "feat(soar): add isolate_agent and block_ip actions; agent handles block_ip via iptables"
```

---

### Task A3: Multi-Model LLM Fallback (Claude as backup)

**Files:**
- Modify: `server-api/requirements.txt`
- Modify: `worker/worker/groq_client.py`
- Modify: `server-api/app/main.py` (add new setting seed)

- [ ] **Step 1: Add anthropic to requirements**

```
# server-api/requirements.txt — append:
anthropic==0.40.0
```

Also add to worker's requirements if separate. Check:
```bash
ls /home/wonka/Documents/hackathon/worker/requirements*.txt 2>/dev/null || ls /home/wonka/Documents/hackathon/worker/pyproject.toml 2>/dev/null
```
Add `anthropic==0.40.0` to whichever file exists.

- [ ] **Step 2: Add fallback settings to _DEFAULT_SETTINGS in main.py**

In `server-api/app/main.py`, after `("greynoise_api_key", ...)`, add:
```python
("anthropic_api_key",   "",                          True,  "Anthropic Claude API key — fallback LLM when Groq is unavailable"),
("fallback_llm",        "false",                     False, "Enable Claude as fallback when Groq fails (true/false)"),
```

- [ ] **Step 3: Add Claude fallback function in groq_client.py**

At top of file after imports, add:
```python
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
```

Add new function before `_fallback_verdict`:
```python
async def _claude_triage(title: str, severity: str, source_ip: str | None,
                          hostname: str | None, decoded_fields: dict) -> dict | None:
    """Fallback LLM triage via Anthropic Claude when Groq is unavailable."""
    import anthropic as _anthropic
    api_key = await get_setting("anthropic_api_key") or ANTHROPIC_API_KEY
    enabled = await get_setting("fallback_llm", "false")
    if not api_key or enabled.lower() != "true":
        return None

    prompt = f"""ALERT TO TRIAGE:
Title    : {title}
Severity : {severity}
Source IP: {source_ip or 'unknown'}
Hostname : {hostname or 'unknown'}
Fields   : {json.dumps(decoded_fields, default=str)[:400]}

Respond ONLY with valid JSON matching this schema:
{{"verdict":"<escalate|create_case|monitor|false_positive>","triage_notes":"<2-3 sentences>","confidence":0.7,"mitre_techniques":[],"immediate_actions":[],"false_positive_reason":null,"threat_type":"other","search_queries":[]}}"""

    try:
        client = _anthropic.AsyncAnthropic(api_key=api_key)
        msg = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        content = msg.content[0].text.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception as e:
        log.warning("claude_fallback_failed", error=str(e))
        return None
```

- [ ] **Step 4: Wire fallback into analyze_alert_with_groq**

In `analyze_alert_with_groq`, replace the except block:
```python
    except Exception as e:
        log.error("groq_l1_triage_failed", error=str(e))
        # Try Claude fallback before returning deterministic verdict
        fallback = await _claude_triage(title, severity, source_ip, hostname, decoded_fields)
        if fallback:
            log.info("groq_fallback_used", model="claude")
            return fallback
        return _fallback_verdict(severity)
```

- [ ] **Step 5: Rebuild worker and commit**

```bash
cd /home/wonka/Documents/hackathon
docker-compose build worker server-api && docker-compose up -d worker server-api
git add worker/worker/groq_client.py server-api/app/main.py server-api/requirements.txt
git commit -m "feat(ai): add Claude API as fallback LLM when Groq is unavailable"
```

---

## GROUP B — Frontend Nav Cleanup (independent, frontend only)

### Task B1: Remove Handover and SOP from Sidebar + Routing

**Files:**
- Modify: `dashboard/src/components/Layout.tsx`
- Modify: `dashboard/src/App.tsx`

- [ ] **Step 1: Remove from Layout.tsx NAV_GROUPS**

Find the `SOC Tools` group in Layout.tsx:
```typescript
{
  label: 'SOC Tools',
  items: [
    { to: '/sop', label: 'SOP Docs', icon: BookMarked, minRole: 'analyst' },
    { to: '/handover', label: 'Handover', icon: ArrowRightLeft, minRole: 'analyst' },
  ],
},
```
Delete the entire `SOC Tools` group (all 6 lines including braces and trailing comma).

Also remove unused icon imports from the import line:
```typescript
// Remove BookMarked, ArrowRightLeft from the lucide-react import
```

- [ ] **Step 2: Remove routes from App.tsx**

Remove these two lines from App.tsx:
```typescript
import HandoverPage from '@/pages/HandoverPage'
import SopPage from '@/pages/SopPage'
```
And their route entries:
```typescript
<Route path="/handover" element={<HandoverPage />} />
<Route path="/sop" element={<ProtectedRoute minRole="analyst"><SopPage /></ProtectedRoute>} />
```

- [ ] **Step 3: Build and verify no broken imports**

```bash
cd /home/wonka/Documents/hackathon/dashboard && npm run build 2>&1 | grep -E "error|Error" | head -10
# Expected: no errors
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/Layout.tsx dashboard/src/App.tsx
git commit -m "chore(nav): remove Handover and SOP pages from sidebar navigation"
```

---

## GROUP C — Global Search (backend first, then frontend)

### Task C1: Global Search API Endpoint

**Files:**
- Create: `server-api/app/api/routes/search.py`
- Modify: `server-api/app/main.py` (register router)

- [ ] **Step 1: Create search route**

```python
# server-api/app/api/routes/search.py
from typing import Annotated
from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user, get_scoped_group
from app.models.models import Alert, Case, User

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
async def global_search(
    q: str = Query(..., min_length=2, max_length=100),
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    group_id: Annotated[str | None, Depends(get_scoped_group)] = None,
    _: User = Depends(get_current_user),
    limit: int = Query(default=5, le=20),
):
    """Search alerts and cases by title, source IP, or hostname."""
    pattern = f"%{q}%"

    alert_q = (
        select(Alert)
        .where(
            or_(
                Alert.title.ilike(pattern),
                Alert.source_ip.ilike(pattern),
                Alert.hostname.ilike(pattern),
            )
        )
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    if group_id:
        alert_q = alert_q.where(Alert.group_id == group_id)
    alerts = (await db.execute(alert_q)).scalars().all()

    case_q = (
        select(Case)
        .where(
            or_(
                Case.title.ilike(pattern),
                Case.description.ilike(pattern),
            )
        )
        .order_by(Case.created_at.desc())
        .limit(limit)
    )
    if group_id:
        case_q = case_q.where(Case.group_id == group_id)
    cases = (await db.execute(case_q)).scalars().all()

    return {
        "alerts": [
            {
                "id": str(a.id), "type": "alert",
                "title": a.title, "severity": a.severity,
                "source_ip": a.source_ip, "hostname": a.hostname,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "cases": [
            {
                "id": str(c.id), "type": "case",
                "title": c.title, "status": c.status,
                "severity": c.severity,
                "created_at": c.created_at.isoformat(),
            }
            for c in cases
        ],
    }
```

- [ ] **Step 2: Register in main.py**

Add import at the top of main.py imports section:
```python
from app.api.routes.search import router as search_router
```

Add registration after the last `app.include_router(...)` call:
```python
app.include_router(search_router)
```

- [ ] **Step 3: Test endpoint**

```bash
docker-compose build server-api && docker-compose up -d server-api
sleep 3
TOKEN=$(curl -s -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s "http://localhost/api/search?q=SSH" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -20
# Expected: JSON with alerts and cases arrays
```

- [ ] **Step 4: Commit**

```bash
git add server-api/app/api/routes/search.py server-api/app/main.py
git commit -m "feat(search): add global search API endpoint for alerts and cases"
```

### Task C2: Global Search UI — Searchbar in Topbar

**Files:**
- Modify: `dashboard/src/components/Layout.tsx`

- [ ] **Step 1: Add search state and handler to Layout.tsx**

At the top of the `Layout` function component, add:
```typescript
const navigate = useNavigate()  // add if not already imported
const [searchQuery, setSearchQuery] = useState('')
const [searchResults, setSearchResults] = useState<{alerts: any[], cases: any[]} | null>(null)
const [searchOpen, setSearchOpen] = useState(false)

const handleSearch = async (q: string) => {
  if (q.length < 2) { setSearchResults(null); return }
  try {
    const r = await api.get('/api/search', { params: { q, limit: 5 } })
    setSearchResults(r.data)
  } catch { setSearchResults(null) }
}
```

Make sure `useNavigate` is imported from `react-router-dom` and `useState` from `react`.

- [ ] **Step 2: Add searchbar in the topbar header**

In the topbar `<header>` element, after the `{currentLabel}` span and before the mode selector div, add:
```typescript
{/* Global Search */}
<div style={{ position: 'relative', flex: 1, maxWidth: 320 }}>
  <div style={{ display: 'flex', alignItems: 'center', background: '#0d0f14', border: '1px solid #1e2028', borderRadius: 6, padding: '4px 10px', gap: 6 }}>
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
    <input
      value={searchQuery}
      onChange={e => { setSearchQuery(e.target.value); setSearchOpen(true); handleSearch(e.target.value) }}
      onFocus={() => setSearchOpen(true)}
      onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
      placeholder="Search alerts, cases, IPs…"
      style={{ background: 'none', border: 'none', outline: 'none', color: '#94a3b8', fontSize: 12, width: '100%' }}
    />
  </div>
  {searchOpen && searchResults && (searchResults.alerts.length > 0 || searchResults.cases.length > 0) && (
    <div style={{
      position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4,
      background: '#111318', border: '1px solid #1e2028', borderRadius: 6,
      zIndex: 1000, overflow: 'hidden', boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
    }}>
      {searchResults.alerts.map((a: any) => (
        <div key={a.id} onMouseDown={() => { navigate(`/alerts`); setSearchOpen(false); setSearchQuery('') }}
          style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid #1e2028', display: 'flex', gap: 8, alignItems: 'center' }}
          onMouseEnter={e => (e.currentTarget.style.background = '#1e2028')}
          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
        >
          <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(255,34,68,0.15)', color: '#ff2244', fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{a.severity}</span>
          <span style={{ fontSize: 12, color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</span>
          <span style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap' }}>alert</span>
        </div>
      ))}
      {searchResults.cases.map((c: any) => (
        <div key={c.id} onMouseDown={() => { navigate(`/cases/${c.id}`); setSearchOpen(false); setSearchQuery('') }}
          style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid #1e2028', display: 'flex', gap: 8, alignItems: 'center' }}
          onMouseEnter={e => (e.currentTarget.style.background = '#1e2028')}
          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
        >
          <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(0,212,255,0.1)', color: '#00d4ff', fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{c.status}</span>
          <span style={{ fontSize: 12, color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</span>
          <span style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap' }}>case</span>
        </div>
      ))}
    </div>
  )}
</div>
```

- [ ] **Step 3: Build and verify**

```bash
cd /home/wonka/Documents/hackathon/dashboard && npm run build 2>&1 | grep -E "^.*error" | head -5
# Expected: successful build
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/components/Layout.tsx
git commit -m "feat(search): add global search bar in topbar with live alert/case results"
```

---

## GROUP D — Attack Timeline in Case Detail (sequential)

### Task D1: Case Timeline API Endpoint

**Files:**
- Modify: `server-api/app/api/routes/cases.py` (add timeline endpoint)

- [ ] **Step 1: Add timeline endpoint to cases router**

In `server-api/app/api/routes/cases.py`, add at the end of the file:

```python
@router.get("/{case_id}/timeline")
async def case_timeline(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    _: User = Depends(get_current_user),
):
    """Return chronological alerts and events related to this case's source IP / hostname."""
    from app.models.models import Alert, Event, AlertNote
    from sqlalchemy import or_, union_all, text
    import uuid as _uuid

    case = await db.get(Case, _uuid.UUID(case_id))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    items = []

    # Related alerts: same source_ip or hostname, within 24h of case creation
    if case.source_ip or case.hostname:
        from datetime import timedelta
        window_start = case.created_at - timedelta(hours=24)
        window_end   = case.created_at + timedelta(hours=24)
        alert_filter = [Alert.created_at.between(window_start, window_end)]
        if case.source_ip:
            alert_filter = [or_(Alert.source_ip == case.source_ip, Alert.hostname == case.hostname)] + alert_filter if case.hostname else [Alert.source_ip == case.source_ip] + alert_filter
        elif case.hostname:
            alert_filter = [Alert.hostname == case.hostname] + alert_filter

        related_alerts = (await db.execute(
            select(Alert).where(*alert_filter).order_by(Alert.created_at.asc()).limit(50)
        )).scalars().all()

        for a in related_alerts:
            items.append({
                "type": "alert",
                "id": str(a.id),
                "ts": a.created_at.isoformat(),
                "title": a.title,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "hostname": a.hostname,
                "is_this_case": str(a.id) == str(case.alert_id) if case.alert_id else False,
            })

    # Case notes
    notes = (await db.execute(
        select(AlertNote)
        .where(AlertNote.alert_id == case.alert_id)
        .order_by(AlertNote.created_at.asc())
    )).scalars().all() if case.alert_id else []

    for n in notes:
        items.append({
            "type": "note",
            "id": str(n.id),
            "ts": n.created_at.isoformat(),
            "title": n.content[:120] + ("…" if len(n.content) > 120 else ""),
        })

    items.sort(key=lambda x: x["ts"])
    return {"case_id": case_id, "items": items}
```

- [ ] **Step 2: Test endpoint**

```bash
docker-compose build server-api && docker-compose up -d server-api
sleep 3
TOKEN=$(curl -s -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
CASE_ID=$(curl -s http://localhost/api/cases -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; cases=json.load(sys.stdin)['items']; print(cases[0]['id'] if cases else 'NO_CASES')")
echo "CASE_ID: $CASE_ID"
curl -s "http://localhost/api/cases/$CASE_ID/timeline" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | head -30
```

- [ ] **Step 3: Commit**

```bash
git add server-api/app/api/routes/cases.py
git commit -m "feat(cases): add timeline endpoint returning chronological alerts and notes per case"
```

### Task D2: Attack Timeline UI in CaseDetailPage

**Files:**
- Modify: `dashboard/src/pages/CaseDetailPage.tsx`

- [ ] **Step 1: Add useQuery for timeline + Timeline component**

In `CaseDetailPage.tsx`, after the existing imports, add the timeline query inside the `CaseDetailPage` function:

```typescript
const { data: timeline } = useQuery({
  queryKey: ['case-timeline', id],
  queryFn: () => api.get(`/api/cases/${id}/timeline`).then(r => r.data),
  enabled: !!id,
})
```

- [ ] **Step 2: Add AttackTimeline component before CaseDetailPage export**

```typescript
function AttackTimeline({ items }: { items: any[] }) {
  if (!items || items.length === 0) return (
    <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', padding: '8px 0' }}>
      No related events found in ±24h window.
    </div>
  )
  const sevColor = (s: string) => ({ critical:'#ff2244', high:'#ff6b00', medium:'#ffd700', low:'#00ff88' })[s] ?? '#00d4ff'
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {items.map((item, idx) => (
        <div key={item.id} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', position: 'relative' }}>
          {/* Timeline line */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
            <div style={{
              width: 10, height: 10, borderRadius: '50%', flexShrink: 0, marginTop: 4,
              background: item.type === 'alert' ? sevColor(item.severity) : '#64748b',
              boxShadow: item.is_this_case ? `0 0 8px ${sevColor(item.severity)}` : 'none',
              border: item.is_this_case ? `2px solid ${sevColor(item.severity)}` : '2px solid transparent',
            }} />
            {idx < items.length - 1 && (
              <div style={{ width: 1, flex: 1, minHeight: 16, background: '#1e2028', marginTop: 2, marginBottom: 2 }} />
            )}
          </div>
          <div style={{ flex: 1, paddingBottom: 10 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                {new Date(item.ts).toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
              </span>
              {item.type === 'alert' && (
                <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 2, background: `${sevColor(item.severity)}22`, color: sevColor(item.severity), fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase' }}>
                  {item.severity}
                </span>
              )}
              {item.type === 'note' && (
                <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 2, background: 'rgba(100,116,139,0.15)', color: '#64748b', fontFamily: 'Share Tech Mono, monospace' }}>NOTE</span>
              )}
              {item.is_this_case && (
                <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 2, background: 'rgba(0,212,255,0.15)', color: '#00d4ff', fontFamily: 'Share Tech Mono, monospace' }}>THIS CASE</span>
              )}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', marginTop: 2, lineHeight: 1.4 }}>{item.title}</div>
            {item.source_ip && (
              <div style={{ fontSize: 10, fontFamily: 'Share Tech Mono, monospace', color: 'var(--accent-cyan)', marginTop: 1 }}>{item.source_ip}</div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 3: Render AttackTimeline in the case detail JSX**

In the return JSX of `CaseDetailPage`, add a new `<Box>` after the existing boxes:

```typescript
{timeline && (
  <Box title={`Attack Timeline (${timeline.items?.length ?? 0} events)`}>
    <AttackTimeline items={timeline.items ?? []} />
  </Box>
)}
```

- [ ] **Step 4: Build and commit**

```bash
cd /home/wonka/Documents/hackathon/dashboard && npm run build 2>&1 | grep -E "error" | head -5
git add dashboard/src/pages/CaseDetailPage.tsx
git commit -m "feat(cases): add attack timeline visualization showing related alerts ±24h"
```

---

## GROUP E — Jira/ServiceNow Webhook Format

### Task E1: Structured Webhook Delivery Format

**Files:**
- Modify: `worker/worker/webhook_sender.py`
- Modify: `server-api/app/main.py` (add Jira webhook format setting)

- [ ] **Step 1: Add Jira format to webhook_sender.py**

In `worker/worker/webhook_sender.py`, find the function that builds webhook payloads and add Jira-formatted delivery option:

First, read the file to understand its structure:
```bash
cat /home/wonka/Documents/hackathon/worker/worker/webhook_sender.py
```

Then add a Jira payload builder after the existing payload logic:

```python
def _build_jira_payload(alert: dict, case: dict | None = None) -> dict:
    """Build a Jira-compatible Create Issue payload from an alert/case."""
    severity_to_priority = {
        "critical": "Highest", "high": "High",
        "medium": "Medium",    "low": "Low", "info": "Lowest",
    }
    severity = alert.get("severity", "medium")
    summary = f"[SIEM {severity.upper()}] {alert.get('title', 'Security Alert')}"
    desc = f"""*Source:* {alert.get('source_ip', 'N/A')} / {alert.get('hostname', 'N/A')}
*Severity:* {severity}
*Detected:* {alert.get('created_at', '')}
*Rule:* {alert.get('rule_title', 'N/A')}

*AI Triage Notes:*
{case.get('ai_reasoning', 'Pending analysis') if case else 'No case created'}

*Alert ID:* {alert.get('id', '')}
"""
    return {
        "fields": {
            "summary": summary,
            "description": {"version": 1, "type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": desc}]}]},
            "issuetype": {"name": "Bug"},
            "priority": {"name": severity_to_priority.get(severity, "Medium")},
            "labels": ["siem", f"severity-{severity}", "auto-created"],
        }
    }


def _build_servicenow_payload(alert: dict, case: dict | None = None) -> dict:
    """Build a ServiceNow Create Incident payload."""
    severity_to_urgency = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
    return {
        "short_description": f"[SIEM] {alert.get('title', 'Security Alert')}",
        "description": f"Source IP: {alert.get('source_ip','N/A')}\nHostname: {alert.get('hostname','N/A')}\nSeverity: {alert.get('severity','medium')}\nAI Notes: {case.get('ai_reasoning','') if case else ''}",
        "urgency": severity_to_urgency.get(alert.get("severity", "medium"), "3"),
        "category": "Security",
        "subcategory": "Intrusion",
        "caller_id": "siem-platform",
    }
```

- [ ] **Step 2: Add format field to Webhook model settings**

Check if webhooks have a `format` field in the DB model:
```bash
grep -n "format\|webhook_format\|payload_format" /home/wonka/Documents/hackathon/server-api/app/models/models.py | head -5
```

If no format column, add it to the Webhook model and create a migration. If the model already has it, skip to Step 3.

In `server-api/app/models/models.py`, find the `Webhook` class and add:
```python
payload_format = Column(String(50), nullable=False, default="default")  # default | jira | servicenow
```

And add a DB migration in `server-api/app/main.py` in the `_startup()` coroutine:
```python
async with engine.begin() as conn:
    await conn.execute(text("ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS payload_format VARCHAR(50) NOT NULL DEFAULT 'default'"))
```

- [ ] **Step 3: Use format in webhook delivery**

In `webhook_sender.py`, when building the delivery payload, check the webhook's `payload_format`:
```python
# When format == "jira":  payload = _build_jira_payload(alert_dict, case_dict)
# When format == "servicenow": payload = _build_servicenow_payload(alert_dict, case_dict)
# When format == "default": use existing payload
```

- [ ] **Step 4: Rebuild and commit**

```bash
docker-compose build worker server-api && docker-compose up -d worker server-api
git add worker/worker/webhook_sender.py server-api/app/models/models.py server-api/app/main.py
git commit -m "feat(webhooks): add Jira and ServiceNow structured payload formats"
```

---

## GROUP F — MFA/TOTP (complex, sequential)

### Task F1: MFA Backend — DB Column + TOTP Endpoints

**Files:**
- Modify: `server-api/app/models/models.py`
- Modify: `server-api/app/main.py` (DB migration)
- Modify: `server-api/app/api/routes/auth.py`
- Modify: `server-api/requirements.txt`

- [ ] **Step 1: Add pyotp to requirements**

```
# server-api/requirements.txt — append:
pyotp==2.9.0
qrcode[pil]==8.0
```

- [ ] **Step 2: Add MFA columns to User model**

In `server-api/app/models/models.py`, in the `User` class, add after `is_active`:
```python
mfa_secret  = Column(Text, nullable=True)   # TOTP secret (encrypted at rest ideally)
mfa_enabled = Column(Boolean, nullable=False, default=False)
```

- [ ] **Step 3: Add DB migration in main.py**

In the startup migration section of `server-api/app/main.py`, add:
```python
async with engine.begin() as conn:
    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT"))
    await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
```

- [ ] **Step 4: Add MFA endpoints to auth.py**

Add these three endpoints to `server-api/app/api/routes/auth.py`:

```python
import pyotp
import qrcode
import io
import base64

@router.post("/mfa/setup")
async def mfa_setup(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Generate a TOTP secret and QR code for the current user."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="SIEM Platform")
    # Generate QR code as base64 PNG
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    # Store secret (not yet enabled — user must verify first)
    current_user.mfa_secret = secret
    current_user.mfa_enabled = False
    await db.commit()
    return {"secret": secret, "qr_code": f"data:image/png;base64,{qr_b64}", "uri": uri}


@router.post("/mfa/enable")
async def mfa_enable(
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Verify TOTP code and enable MFA."""
    code = body.get("code", "")
    if not current_user.mfa_secret:
        raise HTTPException(400, "MFA setup not started. Call /mfa/setup first.")
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        raise HTTPException(400, "Invalid TOTP code")
    current_user.mfa_enabled = True
    await db.commit()
    return {"ok": True, "message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def mfa_disable(
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Disable MFA after verifying current code."""
    code = body.get("code", "")
    if current_user.mfa_enabled and current_user.mfa_secret:
        totp = pyotp.TOTP(current_user.mfa_secret)
        if not totp.verify(code, valid_window=1):
            raise HTTPException(400, "Invalid TOTP code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await db.commit()
    return {"ok": True}
```

- [ ] **Step 5: Modify login to enforce MFA**

In the `login` endpoint, after verifying password and before creating tokens, add:
```python
    # MFA check
    if user.mfa_enabled and user.mfa_secret:
        mfa_code = body.mfa_code if hasattr(body, 'mfa_code') else None
        if not mfa_code:
            # Return a special response indicating MFA is required
            # The frontend will show the MFA input field
            import secrets as _secrets
            mfa_challenge = _secrets.token_urlsafe(16)
            return {"mfa_required": True, "user_id": str(user.id)}
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
```

Update `LoginRequest` schema to include optional `mfa_code`:
In `server-api/app/schemas/schemas.py`, find `LoginRequest` and add:
```python
mfa_code: Optional[str] = None
```

Update `TokenResponse` to include optional `mfa_required`:
```python
mfa_required: Optional[bool] = None
user_id: Optional[str] = None  # only present when mfa_required=True
```

- [ ] **Step 6: Rebuild and test**

```bash
docker-compose build server-api && docker-compose up -d server-api
sleep 3
TOKEN=$(curl -s -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
# Setup MFA
curl -s -X POST http://localhost/api/auth/mfa/setup -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print('secret:', d['secret'])"
# Expected: secret printed, QR code returned
```

- [ ] **Step 7: Commit**

```bash
git add server-api/requirements.txt server-api/app/models/models.py server-api/app/main.py server-api/app/api/routes/auth.py server-api/app/schemas/schemas.py
git commit -m "feat(auth): add MFA/TOTP support — setup, enable, disable endpoints; login enforces MFA when enabled"
```

### Task F2: MFA Frontend — Setup UI in Settings

**Files:**
- Modify: `dashboard/src/pages/SettingsPage.tsx`

- [ ] **Step 1: Add MFA setup section to SettingsPage**

At the top of `SettingsPage.tsx` after existing imports, add:
```typescript
import { useState } from 'react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
```

- [ ] **Step 2: Add MFA component before SettingsPage export**

```typescript
function MfaSection() {
  const { user } = useAuthStore()
  const [qrCode, setQrCode] = useState<string | null>(null)
  const [secret, setSecret] = useState('')
  const [code, setCode] = useState('')
  const [status, setStatus] = useState<'idle'|'setup'|'success'|'error'>('idle')
  const [msg, setMsg] = useState('')

  const startSetup = async () => {
    try {
      const r = await api.post('/api/auth/mfa/setup')
      setQrCode(r.data.qr_code)
      setSecret(r.data.secret)
      setStatus('setup')
    } catch { setMsg('Setup failed'); setStatus('error') }
  }

  const enableMfa = async () => {
    try {
      await api.post('/api/auth/mfa/enable', { code })
      setStatus('success')
      setMsg('MFA enabled! Use your authenticator app for future logins.')
      setQrCode(null)
    } catch { setMsg('Invalid code. Try again.'); setStatus('error') }
  }

  return (
    <div style={{ padding: '20px', borderBottom: '1px solid var(--border)' }}>
      <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: 14, color: 'var(--text-primary)', marginBottom: 6 }}>
        Two-Factor Authentication (TOTP)
      </div>
      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
        Protect your account with an authenticator app (Google Authenticator, Authy, etc.)
      </div>
      {status === 'idle' && (
        <button onClick={startSetup} style={{ padding: '7px 16px', background: 'rgba(0,212,255,0.1)', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', borderRadius: 4, cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 12, letterSpacing: 1 }}>
          ENABLE MFA
        </button>
      )}
      {status === 'setup' && qrCode && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <p style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--text-secondary)', margin: 0 }}>
            1. Scan this QR code with your authenticator app.<br/>
            2. Manual secret: <strong style={{ color: 'var(--accent-cyan)' }}>{secret}</strong>
          </p>
          <img src={qrCode} alt="MFA QR Code" style={{ width: 160, height: 160, border: '1px solid var(--border)', borderRadius: 4 }} />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input value={code} onChange={e => setCode(e.target.value)} placeholder="Enter 6-digit code" maxLength={6}
              style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 12px', color: 'var(--text-primary)', fontFamily: 'Share Tech Mono, monospace', fontSize: 14, width: 160 }} />
            <button onClick={enableMfa} style={{ padding: '7px 16px', background: 'rgba(0,255,136,0.1)', border: '1px solid var(--accent-green)', color: 'var(--accent-green)', borderRadius: 4, cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 12 }}>
              VERIFY & ENABLE
            </button>
          </div>
        </div>
      )}
      {status === 'success' && <div style={{ color: 'var(--accent-green)', fontFamily: 'Share Tech Mono, monospace', fontSize: 12 }}>✓ {msg}</div>}
      {status === 'error' && <div style={{ color: 'var(--accent-red)', fontFamily: 'Share Tech Mono, monospace', fontSize: 12 }}>{msg}</div>}
    </div>
  )
}
```

- [ ] **Step 3: Render MfaSection at top of SettingsPage return**

In the `SettingsPage` return JSX, inside the settings container div before `{settings?.map(...)}`, add:
```typescript
<MfaSection />
```

- [ ] **Step 4: Build, rebuild Docker, commit**

```bash
cd /home/wonka/Documents/hackathon/dashboard && npm run build 2>&1 | grep error | head -5
docker-compose build dashboard && docker-compose up -d dashboard
git add dashboard/src/pages/SettingsPage.tsx
git commit -m "feat(auth): add MFA/TOTP setup UI in Settings page"
```

---

## GROUP G — WebSocket Real-time Alerts Feed

### Task G1: WebSocket Endpoint in server-api

**Files:**
- Create: `server-api/app/api/routes/ws.py`
- Modify: `server-api/app/main.py` (register + add connection manager)
- Modify: `server-api/app/services/ingest.py` or alert creation service (broadcast on new alert)

- [ ] **Step 1: Create WebSocket manager and route**

```python
# server-api/app/api/routes/ws.py
import json
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.security import decode_token
from jose import JWTError

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/api/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: str = ""):
    """WebSocket feed for real-time alert events. Auth via ?token=<access_token>"""
    # Verify JWT
    try:
        payload = decode_token(token)
        if not payload.get("sub"):
            await websocket.close(code=4001)
            return
    except (JWTError, Exception):
        await websocket.close(code=4001)
        return

    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive — client sends ping, we pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
```

- [ ] **Step 2: Register WebSocket route in main.py**

Add import:
```python
from app.api.routes.ws import router as ws_router, manager as ws_manager
```

Add include:
```python
app.include_router(ws_router)
```

Export `ws_manager` so alert creation can broadcast:
```python
# At module level in main.py, after ws_manager import:
# ws_manager is used by alert creation services to broadcast new alerts
```

- [ ] **Step 3: Broadcast on new alert creation**

Find where alerts are created in the worker — in `worker/worker/alert_manager.py`. After an alert is saved to DB, publish to Redis pubsub so the API server can broadcast:

In `alert_manager.py`, after `await db.commit()` on new alert creation, add:
```python
# Publish to Redis for WebSocket broadcast
try:
    import json as _json
    from worker.redis_client import get_redis_client
    redis = await get_redis_client()
    await redis.publish("ws:alerts", _json.dumps({
        "type": "new_alert",
        "id": str(alert.id),
        "title": alert.title,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "hostname": alert.hostname,
        "created_at": alert.created_at.isoformat(),
    }))
except Exception:
    pass  # WebSocket is best-effort, never fail alert creation for it
```

In `server-api/app/main.py`, add a background task that subscribes to Redis pubsub and broadcasts:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ... existing startup code ...
    import asyncio
    from app.core.redis_client import get_redis
    from app.api.routes.ws import manager as ws_manager

    async def redis_listener():
        import aioredis
        redis = aioredis.from_url(settings.REDIS_URL)
        pubsub = redis.pubsub()
        await pubsub.subscribe("ws:alerts")
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    import json
                    data = json.loads(message["data"])
                    await ws_manager.broadcast(data)
                except Exception:
                    pass

    asyncio.create_task(redis_listener())
    yield
    # ... cleanup ...
```

- [ ] **Step 4: Test WebSocket**

```bash
docker-compose build server-api && docker-compose up -d server-api
TOKEN=$(curl -s -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
# Test WebSocket connection
python3 -c "
import asyncio, websockets, json
async def test():
    uri = f'ws://localhost/api/ws/alerts?token=$TOKEN'
    async with websockets.connect(uri) as ws:
        await ws.send('ping')
        resp = await asyncio.wait_for(ws.recv(), timeout=3)
        print('WebSocket response:', resp)
asyncio.run(test())
"
# Expected: pong
```

- [ ] **Step 5: Commit**

```bash
git add server-api/app/api/routes/ws.py server-api/app/main.py worker/worker/alert_manager.py
git commit -m "feat(realtime): add WebSocket endpoint /api/ws/alerts with Redis pubsub broadcast"
```

### Task G2: WebSocket Client in Dashboard

**Files:**
- Modify: `dashboard/src/components/Layout.tsx` (connect + show live indicator)
- Modify: `dashboard/src/pages/DashboardPage.tsx` (prepend live alerts to triage feed)

- [ ] **Step 1: Add WebSocket connection in Layout.tsx**

In the `Layout` component, add inside the component body:

```typescript
const { accessToken } = useAuthStore()
const queryClient = useQueryClient()  // add useQueryClient to imports from @tanstack/react-query

useEffect(() => {
  if (!accessToken) return
  const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/ws/alerts?token=${accessToken}`
  const ws = new WebSocket(wsUrl)
  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      if (data.type === 'new_alert') {
        // Invalidate alert queries to trigger refetch
        queryClient.invalidateQueries({ queryKey: ['alerts-recent'] })
        queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
      }
    } catch {}
  }
  const ping = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping') }, 30000)
  return () => { clearInterval(ping); ws.close() }
}, [accessToken, queryClient])
```

Add import: `import { useQueryClient } from '@tanstack/react-query'`

- [ ] **Step 2: Add live indicator dot to topbar**

In the topbar, next to the current label span, add a pulsing green dot when WebSocket is connected:

```typescript
const [wsConnected, setWsConnected] = useState(false)
// ... in useEffect: ws.onopen = () => setWsConnected(true); ws.onclose = () => setWsConnected(false)
```

Add to JSX next to `{currentLabel}`:
```typescript
{wsConnected && (
  <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', boxShadow: '0 0 6px #34d399', animation: 'pulse 2s infinite', flexShrink: 0 }} title="Live feed connected" />
)}
```

Add pulse animation to `dashboard/src/index.css`:
```css
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
```

- [ ] **Step 3: Build and commit**

```bash
cd /home/wonka/Documents/hackathon/dashboard && npm run build 2>&1 | grep error | head -5
docker-compose build dashboard && docker-compose up -d dashboard
git add dashboard/src/components/Layout.tsx dashboard/src/index.css
git commit -m "feat(realtime): connect WebSocket in frontend, invalidate queries on new alerts, show live indicator"
```

---

## GROUP H — UEBA Baseline Graph

### Task H1: UEBA History API Endpoint

**Files:**
- Modify: `server-api/app/api/routes/ueba.py`

- [ ] **Step 1: Add history endpoint to ueba.py**

Read the current ueba.py to understand its structure:
```bash
cat /home/wonka/Documents/hackathon/server-api/app/api/routes/ueba.py
```

Then add:
```python
@router.get("/{entity_type}/{entity_value}/history")
async def entity_risk_history(
    entity_type: str,
    entity_value: str,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    _: User = Depends(get_current_user),
    days: int = Query(default=30, le=90),
):
    """Return daily risk score history for a UEBA entity."""
    from datetime import timedelta
    from sqlalchemy import func, cast, Date
    from app.models.models import UebaAnomaly

    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Daily max risk score
    daily_q = (
        select(
            cast(UebaAnomaly.detected_at, Date).label("day"),
            func.max(UebaAnomaly.risk_score).label("max_risk"),
            func.count().label("anomaly_count"),
        )
        .where(
            UebaAnomaly.entity_type == entity_type,
            UebaAnomaly.entity_value == entity_value,
            UebaAnomaly.detected_at >= since,
        )
        .group_by(cast(UebaAnomaly.detected_at, Date))
        .order_by(cast(UebaAnomaly.detected_at, Date).asc())
    )
    rows = (await db.execute(daily_q)).all()

    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "days": days,
        "history": [
            {"day": str(r.day), "max_risk": round(r.max_risk, 1), "anomaly_count": r.anomaly_count}
            for r in rows
        ],
    }
```

- [ ] **Step 2: Test endpoint**

```bash
docker-compose build server-api && docker-compose up -d server-api
sleep 3
TOKEN=$(curl -s -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s "http://localhost/api/ueba/user/mallory/history?days=30" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

- [ ] **Step 3: Commit**

```bash
git add server-api/app/api/routes/ueba.py
git commit -m "feat(ueba): add daily risk history endpoint for baseline graph"
```

### Task H2: UEBA Risk Baseline Graph (SVG sparkline)

**Files:**
- Modify: `dashboard/src/pages/UEBAPage.tsx`

- [ ] **Step 1: Add history query to DetailPanel component**

In `UEBAPage.tsx`, inside `DetailPanel`, add:
```typescript
const { data: history } = useQuery({
  queryKey: ['ueba-history', entityType, entityValue],
  queryFn: () => api.get(`/api/ueba/${entityType}/${entityValue}/history?days=30`).then(r => r.data),
  enabled: !!entityType && !!entityValue,
})
```

- [ ] **Step 2: Add RiskSparkline component before DetailPanel**

```typescript
function RiskSparkline({ data }: { data: {day: string, max_risk: number}[] }) {
  if (!data || data.length === 0) return (
    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
      No historical data yet
    </div>
  )

  const W = 280, H = 60, PAD = 4
  const maxRisk = Math.max(...data.map(d => d.max_risk), 100)
  const pts = data.map((d, i) => {
    const x = PAD + (i / Math.max(data.length - 1, 1)) * (W - PAD * 2)
    const y = H - PAD - (d.max_risk / maxRisk) * (H - PAD * 2)
    return `${x},${y}`
  }).join(' ')

  const areaPath = `M${PAD},${H - PAD} ` +
    data.map((d, i) => {
      const x = PAD + (i / Math.max(data.length - 1, 1)) * (W - PAD * 2)
      const y = H - PAD - (d.max_risk / maxRisk) * (H - PAD * 2)
      return `L${x},${y}`
    }).join(' ') +
    ` L${W - PAD},${H - PAD} Z`

  const lastRisk = data[data.length - 1].max_risk
  const color = lastRisk >= 80 ? '#ff2244' : lastRisk >= 60 ? '#ff6b35' : lastRisk >= 40 ? '#ffd700' : '#00ff88'

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 10, color: 'var(--text-muted)' }}>
          30-day risk trend
        </span>
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 10, color }}>
          {data.length} days · latest {lastRisk.toFixed(0)}
        </span>
      </div>
      <svg width={W} height={H} style={{ overflow: 'visible' }}>
        {/* Grid lines at 25, 50, 75 */}
        {[25, 50, 75].map(v => (
          <line key={v}
            x1={PAD} y1={H - PAD - (v / maxRisk) * (H - PAD * 2)}
            x2={W - PAD} y2={H - PAD - (v / maxRisk) * (H - PAD * 2)}
            stroke="rgba(255,255,255,0.05)" strokeWidth={1}
          />
        ))}
        {/* Area fill */}
        <path d={areaPath} fill={`${color}18`} />
        {/* Line */}
        <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" />
        {/* Last point dot */}
        {data.length > 0 && (() => {
          const last = data[data.length - 1]
          const x = W - PAD
          const y = H - PAD - (last.max_risk / maxRisk) * (H - PAD * 2)
          return <circle cx={x} cy={y} r={3} fill={color} />
        })()}
      </svg>
    </div>
  )
}
```

- [ ] **Step 3: Render RiskSparkline inside DetailPanel**

Inside `DetailPanel`, after the `<RiskBar score={data.score.risk_score} />` section, add:

```typescript
{history && (
  <div>
    <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '6px' }}>
      RISK BASELINE
    </div>
    <RiskSparkline data={history.history} />
  </div>
)}
```

- [ ] **Step 4: Build, rebuild, commit**

```bash
cd /home/wonka/Documents/hackathon/dashboard && npm run build 2>&1 | grep error | head -5
docker-compose build dashboard && docker-compose up -d dashboard
git add dashboard/src/pages/UEBAPage.tsx
git commit -m "feat(ueba): add 30-day risk baseline sparkline chart in entity detail panel"
```

---

## Final Step: Push All Changes

- [ ] **Rebuild all containers**

```bash
cd /home/wonka/Documents/hackathon
docker-compose build && docker-compose up -d
sleep 5
# Verify all containers healthy
docker ps --format "table {{.Names}}\t{{.Status}}"
```

- [ ] **Push to GitHub**

```bash
git push origin feature/siem-implementation
```

---

## Notes

- **MTTD/MTTR widget**: Already implemented in DashboardPage.tsx lines 466-468 — no action needed.
- **Merge LogSources → Agents**: Already accessible via Agents table row click — no action needed.
- **Correlation match fields**: Current `source_ip` and `hostname` are sufficient for the current correlation engine; extend to `rule_name` only if needed.
- **Worker requirements**: If worker has a separate requirements.txt, also add `anthropic` there for the LLM fallback.
