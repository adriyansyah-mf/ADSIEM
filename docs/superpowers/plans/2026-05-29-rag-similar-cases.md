# RAG Similar Cases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inject top-3 semantically similar resolved cases into the Groq L1 triage prompt so the AI analyst learns from past investigator decisions.

**Architecture:** Switch Postgres to the pgvector-enabled image, store 384-dim embeddings of resolved cases in a `case_embeddings` table, query cosine similarity at triage time, and prepend matching cases to the Groq prompt as "Pembelajaran dari kasus sebelumnya." A background indexer runs hourly to keep embeddings up-to-date without blocking the hot path.

**Tech Stack:** `pgvector/pgvector:pg16` (Docker image), `fastembed>=0.3.6` (`BAAI/bge-small-en-v1.5`, 384 dims, ~33 MB), `pgvector>=0.3.6` (SQLAlchemy column type), existing asyncpg + SQLAlchemy 2.0 async stack.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `docker-compose.yml` | Modify | Switch postgres image to pgvector variant |
| `db/init.sql` | Modify | Enable `vector` extension; create `case_embeddings` table |
| `server-api/app/main.py` | Modify | Add startup migration for `case_embeddings` + vector extension |
| `worker/requirements.txt` | Modify | Add `fastembed`, `pgvector` |
| `worker/worker/models.py` | Modify | Add `CaseEmbedding` SQLAlchemy model |
| `worker/worker/rag.py` | Create | Embed text, index case, retrieve similar cases |
| `worker/worker/rag_indexer.py` | Create | Background loop to index resolved/closed cases |
| `worker/worker/main.py` | Modify | Start `rag_index_loop` background task |
| `worker/worker/ai_analyst.py` | Modify | Call `retrieve_similar_cases` before Groq; pass results in |
| `worker/worker/groq_client.py` | Modify | Accept + inject `similar_cases` into L1 prompt |
| `worker/tests/test_rag.py` | Create | Unit tests for embed + retrieve |

---

## Task 1: Switch Postgres to pgvector image

**Files:**
- Modify: `docker-compose.yml:6`
- Modify: `db/init.sql:3`

- [ ] **Step 1: Update docker-compose.yml postgres image**

Change line 6 from `image: postgres:16-alpine` to:

```yaml
  postgres:
    image: pgvector/pgvector:pg16
```

> `pgvector/pgvector:pg16` is the official pgvector image based on Postgres 16 (Debian-based, drop-in replacement). The existing `postgres_data` volume is fully compatible.

- [ ] **Step 2: Enable vector extension in init.sql**

After the existing `CREATE EXTENSION IF NOT EXISTS "pgcrypto";` line (line 3), add:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

- [ ] **Step 3: Verify the image is available**

```bash
docker pull pgvector/pgvector:pg16
```

Expected: `Status: Downloaded newer image for pgvector/pgvector:pg16` (or "Image is up to date")

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml db/init.sql
git commit -m "feat(rag): switch postgres to pgvector/pgvector:pg16 image"
```

---

## Task 2: case_embeddings table — migration + model

**Files:**
- Modify: `server-api/app/main.py` (inside `_migrate_alerts_columns`)
- Modify: `worker/worker/models.py`

- [ ] **Step 1: Write failing test for model existence**

Create `worker/tests/test_rag.py`:

```python
# worker/tests/test_rag.py
import pytest

def test_case_embedding_model_has_required_fields():
    from worker.models import CaseEmbedding
    cols = {c.name for c in CaseEmbedding.__table__.columns}
    assert "case_id" in cols
    assert "group_id" in cols
    assert "embedding" in cols
    assert "summary_text" in cols
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_rag.py::test_case_embedding_model_has_required_fields -v
```

Expected: FAIL with `ImportError: cannot import name 'CaseEmbedding'`

- [ ] **Step 3: Add CaseEmbedding to worker models**

Open `worker/worker/models.py`. Add at the very top of imports (after existing sqlalchemy imports):

```python
from pgvector.sqlalchemy import Vector
```

Then add the model after the `CaseNote` class (around line 129):

```python
class CaseEmbedding(Base):
    __tablename__ = "case_embeddings"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id      = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"),
                          nullable=False, unique=True)
    group_id     = Column(String(100), nullable=False, default="default")
    embedding    = Column(Vector(384), nullable=False)
    summary_text = Column(Text, nullable=False)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_rag.py::test_case_embedding_model_has_required_fields -v
```

Expected: PASS

- [ ] **Step 5: Add startup migration in server-api/app/main.py**

Inside `_migrate_alerts_columns()`, after the existing `ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_confidence FLOAT` block, add:

```python
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS case_embeddings (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                embedding    vector(384) NOT NULL,
                summary_text TEXT NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                CONSTRAINT uq_case_embeddings_case_id UNIQUE (case_id)
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_case_embeddings_group
            ON case_embeddings(group_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_case_embeddings_ivfflat
            ON case_embeddings
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 10)
        """))
```

- [ ] **Step 6: Commit**

```bash
git add worker/worker/models.py worker/tests/test_rag.py server-api/app/main.py
git commit -m "feat(rag): add CaseEmbedding model and case_embeddings migration"
```

---

## Task 3: RAG core module — embed + index + retrieve

**Files:**
- Modify: `worker/requirements.txt`
- Create: `worker/worker/rag.py`
- Test: `worker/tests/test_rag.py`

- [ ] **Step 1: Add dependencies to requirements.txt**

Append to `worker/requirements.txt`:

```
fastembed>=0.3.6
pgvector>=0.3.6
```

- [ ] **Step 2: Write failing tests**

Add to `worker/tests/test_rag.py`:

```python
def test_embed_text_returns_384_dimensions():
    from worker.rag import embed_text
    vec = embed_text("SSH brute force attack detected from 1.2.3.4")
    assert isinstance(vec, list)
    assert len(vec) == 384
    assert all(isinstance(v, float) for v in vec)


def test_embed_text_different_inputs_differ():
    from worker.rag import embed_text
    v1 = embed_text("SSH brute force")
    v2 = embed_text("DNS exfiltration via TXT records")
    assert v1 != v2


def test_retrieve_similar_cases_returns_list():
    from unittest.mock import AsyncMock, patch, MagicMock
    import asyncio

    async def run():
        with patch("worker.rag.AsyncSessionLocal") as mock_session_cls:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_result = MagicMock()
            mock_result.mappings.return_value.all.return_value = []
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session_cls.return_value = mock_session

            from worker.rag import retrieve_similar_cases
            result = await retrieve_similar_cases("SSH brute force", "default")
            assert isinstance(result, list)

    asyncio.run(run())
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
pip install fastembed pgvector  # install locally for test run
python -m pytest tests/test_rag.py -v -k "embed or retrieve"
```

Expected: FAIL with `ModuleNotFoundError: No module named 'worker.rag'`

- [ ] **Step 4: Create worker/worker/rag.py**

```python
# worker/worker/rag.py
"""RAG — embed resolved cases and retrieve similar ones at triage time."""
from __future__ import annotations
import uuid
from typing import Optional

import structlog
from sqlalchemy import text

from worker.database import AsyncSessionLocal

log = structlog.get_logger()

_embedder = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding
        _embedder = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
    return _embedder


def embed_text(text: str) -> list[float]:
    """Return 384-dim embedding vector for text."""
    embedder = _get_embedder()
    vectors = list(embedder.embed([text]))
    return vectors[0].tolist()


async def index_case(
    case_id: str,
    title: str,
    description: Optional[str],
    verdict: str,
    group_id: str,
) -> None:
    """Embed a resolved case and upsert into case_embeddings."""
    summary = f"{title}\n{description or ''}\nVerdict: {verdict}".strip()
    try:
        vector = embed_text(summary)
    except Exception as e:
        log.warning("rag_embed_failed", case_id=case_id, error=str(e))
        return

    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("""
                INSERT INTO case_embeddings (id, case_id, group_id, embedding, summary_text)
                VALUES (:id, :case_id, :group_id, :embedding, :summary_text)
                ON CONFLICT (case_id) DO UPDATE
                    SET embedding = EXCLUDED.embedding,
                        summary_text = EXCLUDED.summary_text
            """), {
                "id": str(uuid.uuid4()),
                "case_id": case_id,
                "group_id": group_id,
                "embedding": str(vector),
                "summary_text": summary,
            })
            await db.commit()
        log.info("rag_case_indexed", case_id=case_id)
    except Exception as e:
        log.warning("rag_index_failed", case_id=case_id, error=str(e))


async def retrieve_similar_cases(
    query_text: str,
    group_id: str,
    top_k: int = 3,
    min_score: float = 0.60,
) -> list[dict]:
    """
    Return top-k resolved/closed cases most similar to query_text.
    Each result: {title, description, verdict, similarity, case_id}
    """
    try:
        vector = embed_text(query_text)
    except Exception as e:
        log.warning("rag_embed_query_failed", error=str(e))
        return []

    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT
                    c.id::text                                           AS case_id,
                    c.title,
                    c.description,
                    c.status,
                    1 - (ce.embedding <=> :embedding::vector)           AS similarity
                FROM case_embeddings ce
                JOIN cases c ON c.id = ce.case_id
                WHERE ce.group_id = :group_id
                  AND c.status IN ('resolved', 'closed')
                  AND 1 - (ce.embedding <=> :embedding::vector) >= :min_score
                ORDER BY ce.embedding <=> :embedding::vector
                LIMIT :top_k
            """), {
                "embedding": str(vector),
                "group_id": group_id,
                "min_score": min_score,
                "top_k": top_k,
            })).mappings().all()
            return [dict(r) for r in rows]
    except Exception as e:
        log.warning("rag_retrieve_failed", error=str(e))
        return []
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_rag.py -v -k "embed or retrieve"
```

Expected: all 3 tests PASS (first run downloads ~33 MB model)

- [ ] **Step 6: Commit**

```bash
git add worker/requirements.txt worker/worker/rag.py worker/tests/test_rag.py
git commit -m "feat(rag): add rag.py — embed_text, index_case, retrieve_similar_cases"
```

---

## Task 4: Background indexer loop

**Files:**
- Create: `worker/worker/rag_indexer.py`
- Modify: `worker/worker/main.py`

- [ ] **Step 1: Write failing test**

Add to `worker/tests/test_rag.py`:

```python
def test_rag_indexer_module_importable():
    from worker.rag_indexer import rag_index_loop
    import asyncio
    assert asyncio.iscoroutinefunction(rag_index_loop)
```

- [ ] **Step 2: Run to verify it fails**

```bash
python -m pytest tests/test_rag.py::test_rag_indexer_module_importable -v
```

Expected: FAIL with `ImportError: cannot import name 'rag_index_loop'`

- [ ] **Step 3: Create worker/worker/rag_indexer.py**

```python
# worker/worker/rag_indexer.py
"""Background loop: index resolved/closed cases that don't have embeddings yet."""
import asyncio
import structlog
from sqlalchemy import text
from worker.database import AsyncSessionLocal
from worker.rag import index_case

log = structlog.get_logger()
INDEX_INTERVAL = 3600  # once per hour


async def rag_index_loop() -> None:
    await asyncio.sleep(60)  # let server start first
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
                    SELECT c.id::text, c.title, c.description, c.status, c.group_id
                    FROM cases c
                    LEFT JOIN case_embeddings ce ON ce.case_id = c.id
                    WHERE c.status IN ('resolved', 'closed')
                      AND ce.case_id IS NULL
                    ORDER BY c.updated_at DESC
                    LIMIT 100
                """))).mappings().all()

            if rows:
                log.info("rag_indexer_batch", count=len(rows))
                for row in rows:
                    await index_case(
                        case_id=row["id"],
                        title=row["title"],
                        description=row["description"],
                        verdict=row["status"],
                        group_id=row["group_id"],
                    )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("rag_indexer_error", error=str(e))

        await asyncio.sleep(INDEX_INTERVAL)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_rag.py::test_rag_indexer_module_importable -v
```

Expected: PASS

- [ ] **Step 5: Start rag_index_loop in worker/worker/main.py**

Open `worker/worker/main.py`. Find the section where other background tasks are started (look for `asyncio.ensure_future` or `asyncio.create_task` calls near campaign_analyzer, ai_consumer, agent_monitor, etc.).

Add the import at the top of the file with other imports:

```python
from worker.rag_indexer import rag_index_loop
```

Then add the task alongside the other background tasks (find the pattern and match it):

```python
asyncio.ensure_future(rag_index_loop())
```

- [ ] **Step 6: Commit**

```bash
git add worker/worker/rag_indexer.py worker/worker/main.py worker/tests/test_rag.py
git commit -m "feat(rag): add rag_indexer background loop to embed resolved cases"
```

---

## Task 5: Inject similar cases into Groq L1 triage prompt

**Files:**
- Modify: `worker/worker/groq_client.py:85-156` (`analyze_alert_with_groq`)
- Modify: `worker/worker/ai_analyst.py:313-440` (`analyze_and_maybe_create_case`)

- [ ] **Step 1: Write failing test**

Add to `worker/tests/test_rag.py`:

```python
def test_analyze_alert_accepts_similar_cases_param():
    import inspect
    from worker.groq_client import analyze_alert_with_groq
    sig = inspect.signature(analyze_alert_with_groq)
    assert "similar_cases" in sig.parameters
```

- [ ] **Step 2: Run to verify it fails**

```bash
python -m pytest tests/test_rag.py::test_analyze_alert_accepts_similar_cases_param -v
```

Expected: FAIL with `AssertionError` (parameter doesn't exist yet)

- [ ] **Step 3: Add similar_cases param to analyze_alert_with_groq**

In `worker/worker/groq_client.py`, change the signature of `analyze_alert_with_groq` (currently at line 85) to add the new parameter:

```python
async def analyze_alert_with_groq(
    title: str,
    severity: str,
    source_ip: str | None,
    hostname: str | None,
    decoded_fields: dict,
    enrichment=None,
    heuristic_mitre: list[str] | None = None,
    search_results: list[dict] | None = None,
    similar_cases: list[dict] | None = None,
) -> dict:
```

Then inside the function, after the `mitre_hint` line (currently around line 116) and before `prompt = f"""`, add:

```python
    similar_cases_section = ""
    if similar_cases:
        lines = []
        for i, c in enumerate(similar_cases[:3], 1):
            sim_pct = int(float(c.get("similarity", 0)) * 100)
            desc = (c.get("description") or "")[:200]
            lines.append(
                f"{i}. [{c.get('status','?').upper()}] {c.get('title','?')} "
                f"(similarity: {sim_pct}%)\n   {desc}"
            )
        similar_cases_section = "\n\nPEMBELAJARAN DARI KASUS SEBELUMNYA:\n" + "\n".join(lines)
```

Then add `{similar_cases_section}` to the prompt f-string, just before the final `\n\nLakukan triage...` line:

```python
    prompt = f"""ALERT UNTUK DITRIAGE:
Title    : {title}
Severity : {severity}
Source IP: {source_ip or 'tidak diketahui'}
Hostname : {hostname or 'tidak diketahui'}
Fields   : {json.dumps(decoded_fields, default=str)[:500]}{ioc_list}{mitre_hint}{enrichment_section}{similar_cases_section}

Lakukan triage dan berikan verdict-mu sebagai analis L1."""
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_rag.py::test_analyze_alert_accepts_similar_cases_param -v
```

Expected: PASS

- [ ] **Step 5: Call retrieve_similar_cases in ai_analyst.py**

In `worker/worker/ai_analyst.py`, add the import at the top:

```python
from worker.rag import retrieve_similar_cases
```

Then in `analyze_and_maybe_create_case`, between step `# ── 2. Eskalasi severity dari TI` and `# ── 3. Groq L1 triage` (around line 347), add:

```python
    # ── 2b. RAG — kasus serupa dari masa lalu ───────────────────────────────
    query_text = f"{title}\n{source_ip or ''}\n{hostname or ''}"
    similar_cases = await retrieve_similar_cases(query_text, group_id)
    if similar_cases:
        log.info("rag_similar_found", alert_id=alert_id, count=len(similar_cases),
                 top_similarity=round(float(similar_cases[0].get("similarity", 0)), 2))
```

Then pass `similar_cases` to the Groq call (currently at line 348):

```python
    analysis = await analyze_alert_with_groq(
        title=title,
        severity=effective_severity,
        source_ip=source_ip,
        hostname=hostname,
        decoded_fields=decoded_fields,
        enrichment=enrichment,
        heuristic_mitre=heuristic_mitre,
        similar_cases=similar_cases if similar_cases else None,
    )
```

- [ ] **Step 6: Run full test suite**

```bash
python -m pytest tests/test_rag.py -v
```

Expected: all tests PASS

- [ ] **Step 7: Commit**

```bash
git add worker/worker/groq_client.py worker/worker/ai_analyst.py worker/tests/test_rag.py
git commit -m "feat(rag): inject top-3 similar resolved cases into Groq L1 triage prompt"
```

---

## Task 6: Index new resolved cases immediately (hook on verdict)

**Files:**
- Modify: `worker/worker/ai_analyst.py` (`_create_case_from_verdict`)

This prevents a 1-hour lag between a case resolving via AI FP verdict and being available for retrieval. When the AI marks something false_positive and closes the alert, we don't create a case — but when a case is created and then later resolved, we want to index it. The trigger point for indexing is when the **case status changes to resolved/closed via the API**.

Since the API case update route already exists in `server-api/app/api/routes/cases.py`, we add an async task there.

- [ ] **Step 1: Find the PATCH handler in server-api cases route**

```bash
grep -n "def update_case\|PATCH\|status" /home/wonka/Documents/hackathon/server-api/app/api/routes/cases.py | head -20
```

- [ ] **Step 2: Add background indexing trigger via Redis**

In `server-api/app/api/routes/cases.py`, after a successful status update to `resolved` or `closed`, push the case_id to a Redis key `rag:index:queue` so the worker can pick it up:

```python
# After db.commit() in the PATCH handler, add:
if update_data.get("status") in ("resolved", "closed"):
    try:
        import aioredis, os, json as _json
        r = await aioredis.from_url(os.getenv("REDIS_URL", "redis://redis:6379"))
        await r.rpush("rag:index:queue", _json.dumps({"case_id": str(case.id), "group_id": case.group_id}))
        await r.aclose()
    except Exception:
        pass  # non-critical, background indexer will catch it
```

Actually this introduces a new Redis client in server-api. Given the existing architecture where worker handles all async jobs, it's simpler to rely solely on the **hourly background indexer** (already built in Task 4) and skip this task. The 1-hour lag is acceptable. **Skip this task.**

---

## Task 7: Smoke test end-to-end

**Files:**
- No code changes

- [ ] **Step 1: Rebuild and restart with new postgres image**

```bash
cd /home/wonka/Documents/hackathon
docker compose down
docker compose up -d --build
```

> **Note:** First worker startup downloads FastEmbed model (~33 MB). Watch logs:
> ```bash
> docker compose logs -f worker | grep -i "rag\|fastembed\|embed"
> ```
> Expected: `rag_case_indexed` or `rag_indexer_batch` after any resolved cases exist.

- [ ] **Step 2: Verify vector extension enabled**

```bash
docker exec siem-platform-postgres-1 psql -U soc -d soc_platform -c "\dx" | grep vector
```

Expected: `vector | ... | functions, operators, and index access methods for exact and approximate vector similarity search`

- [ ] **Step 3: Verify case_embeddings table exists**

```bash
docker exec siem-platform-postgres-1 psql -U soc -d soc_platform -c "\d case_embeddings"
```

Expected: table with columns `id, case_id, group_id, embedding, summary_text, created_at`

- [ ] **Step 4: Manually resolve a case and check embedding is created**

```bash
# Resolve a case via API (replace UUID with a real case id):
curl -s -X PATCH http://localhost/api/cases/<UUID> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved"}' | jq .status
```

Then within 1 hour (or trigger worker restart to run indexer sooner):

```bash
docker exec siem-platform-postgres-1 psql -U soc -d soc_platform \
  -c "SELECT case_id, length(summary_text) FROM case_embeddings LIMIT 5;"
```

Expected: rows with non-zero `length(summary_text)`

- [ ] **Step 5: Verify RAG context appears in new alert triage**

Watch worker logs when a new alert fires:

```bash
docker compose logs -f worker | grep -E "rag_similar|ai_l1_triage"
```

Expected once enough resolved cases exist:
```
{"event": "rag_similar_found", "alert_id": "...", "count": 2, "top_similarity": 0.87}
{"event": "ai_l1_triage_done", "verdict": "...", ...}
```

- [ ] **Step 6: Final commit**

```bash
git add .
git commit -m "feat(rag): end-to-end RAG similar cases — pgvector + fastembed integrated"
```

---

## Self-Review

**Spec coverage:**
- ✅ pgvector infrastructure (Task 1)
- ✅ case_embeddings table + model (Task 2)
- ✅ embed_text + index_case + retrieve_similar_cases (Task 3)
- ✅ Background indexer for existing resolved cases (Task 4)
- ✅ Injection into Groq prompt (Task 5)
- ✅ Smoke test (Task 7)
- ✅ FastEmbed `BAAI/bge-small-en-v1.5`, 384 dims
- ✅ Top-3 retrieval, min 60% cosine similarity threshold

**No placeholders found.**

**Type consistency check:**
- `index_case(case_id: str, title: str, description: Optional[str], verdict: str, group_id: str)` — used consistently in Task 3 and Task 4
- `retrieve_similar_cases(query_text: str, group_id: str, top_k: int = 3, min_score: float = 0.60) -> list[dict]` — called in Task 5 with matching signature
- `similar_cases` passed as `list[dict] | None` from Task 5 ai_analyst call to groq_client — consistent
- `CaseEmbedding` model defined in Task 2, imported in rag.py via `from worker.models import CaseEmbedding` — actually rag.py uses raw SQL, not the ORM model, so no import needed there. Consistent.
