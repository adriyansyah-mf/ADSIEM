# RAG: Similar Cases + Company SOP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inject two RAG knowledge sources into the Groq L1 triage prompt: (1) top-3 semantically similar resolved cases so the AI learns from past investigator decisions, and (2) relevant excerpts from company-uploaded Incident Handling SOPs so the AI follows company-specific procedures when writing case notes.

**Architecture:** Switch Postgres to the pgvector-enabled image. Two separate embedding tables: `case_embeddings` for past cases (indexed hourly by background worker) and `sop_chunks` for SOP document paragraphs (indexed on upload). Both retrieved via cosine similarity at triage time and injected as separate sections in the Groq prompt. Users upload SOP documents (PDF/DOCX/TXT) via a dedicated dashboard page; server-api extracts the text and stores it; the worker chunks and embeds it.

**Tech Stack:** `pgvector/pgvector:pg16` (Docker image), `fastembed>=0.3.6` (`BAAI/bge-small-en-v1.5`, 384 dims, ~33 MB), `pgvector>=0.3.6` (SQLAlchemy column type), `pypdf>=4.0` + `python-docx>=1.1` (server-api text extraction), existing asyncpg + SQLAlchemy 2.0 async + React/TanStack Query stack.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `docker-compose.yml` | Modify | Switch postgres image to pgvector variant |
| `db/init.sql` | Modify | Enable `vector` extension; create `case_embeddings` table |
| `server-api/app/main.py` | Modify | Startup migrations: `case_embeddings`, `sop_documents`, `sop_chunks` |
| `server-api/app/models/models.py` | Modify | Add `SopDocument` + `SopChunk` SQLAlchemy models |
| `server-api/app/schemas/schemas.py` | Modify | Add `SopDocumentOut`, `SopDocumentCreate` Pydantic schemas |
| `server-api/app/api/routes/sop.py` | Create | POST/GET/DELETE `/api/sop-documents` upload + list + delete |
| `server-api/requirements.txt` | Modify | Add `pypdf`, `python-docx` |
| `worker/requirements.txt` | Modify | Add `fastembed`, `pgvector` |
| `worker/worker/models.py` | Modify | Add `CaseEmbedding` + `SopDocument` + `SopChunk` SQLAlchemy models |
| `worker/worker/rag.py` | Create | `embed_text`, `index_case`, `retrieve_similar_cases`, `index_sop_document`, `retrieve_sop_context` |
| `worker/worker/rag_indexer.py` | Create | Background loops: index resolved cases + pending SOP documents |
| `worker/worker/main.py` | Modify | Start `rag_index_loop` background task |
| `worker/worker/ai_analyst.py` | Modify | Call both retrieve functions before Groq; pass results in |
| `worker/worker/groq_client.py` | Modify | Accept + inject `similar_cases` + `sop_context` into L1 prompt |
| `worker/tests/test_rag.py` | Create | Unit tests for embed, retrieve cases, retrieve SOP |
| `dashboard/src/pages/SopPage.tsx` | Create | Upload + list + delete SOP documents |
| `dashboard/src/App.tsx` | Modify | Add `/sop` route |
| `dashboard/src/components/Sidebar.tsx` | Modify | Add SOP nav item |

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

## Task 7: SOP tables + models + migration

**Files:**
- Modify: `server-api/app/main.py` (inside `_migrate_alerts_columns`)
- Modify: `server-api/app/models/models.py`
- Modify: `worker/worker/models.py`

- [ ] **Step 1: Write failing test**

Add to `worker/tests/test_rag.py`:

```python
def test_sop_models_have_required_fields():
    from worker.models import SopDocument, SopChunk
    doc_cols = {c.name for c in SopDocument.__table__.columns}
    assert {"group_id", "filename", "raw_text", "status"}.issubset(doc_cols)
    chunk_cols = {c.name for c in SopChunk.__table__.columns}
    assert {"document_id", "group_id", "chunk_index", "chunk_text", "embedding"}.issubset(chunk_cols)
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /home/wonka/Documents/hackathon/worker
python -m pytest tests/test_rag.py::test_sop_models_have_required_fields -v
```

Expected: FAIL with `ImportError: cannot import name 'SopDocument'`

- [ ] **Step 3: Add SopDocument + SopChunk to worker/worker/models.py**

After the `CaseEmbedding` class (added in Task 2), add:

```python
class SopDocument(Base):
    __tablename__ = "sop_documents"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id     = Column(String(100), nullable=False, default="default")
    filename     = Column(String(500), nullable=False)
    content_type = Column(String(100), nullable=False, default="text/plain")
    raw_text     = Column(Text, nullable=False)
    status       = Column(String(20), nullable=False, default="pending")  # pending/indexed/failed
    uploaded_by  = Column(UUID(as_uuid=True))
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class SopChunk(Base):
    __tablename__ = "sop_chunks"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id  = Column(UUID(as_uuid=True), ForeignKey("sop_documents.id", ondelete="CASCADE"),
                          nullable=False)
    group_id     = Column(String(100), nullable=False, default="default")
    chunk_index  = Column(Integer, nullable=False)
    chunk_text   = Column(Text, nullable=False)
    embedding    = Column(Vector(384), nullable=False)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
```

- [ ] **Step 4: Add same models to server-api/app/models/models.py**

Open `server-api/app/models/models.py`. After the last model class, add (re-using the same Vector import already added for CaseEmbedding in Task 2, but here we need it for server-api too — check if `from pgvector.sqlalchemy import Vector` is at the top of that file first; if not, add it):

```python
class SopDocument(Base):
    __tablename__ = "sop_documents"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id     = Column(String(100), nullable=False, default="default")
    filename     = Column(String(500), nullable=False)
    content_type = Column(String(100), nullable=False, default="text/plain")
    raw_text     = Column(Text, nullable=False)
    status       = Column(String(20), nullable=False, default="pending")
    uploaded_by  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class SopChunk(Base):
    __tablename__ = "sop_chunks"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id  = Column(UUID(as_uuid=True), ForeignKey("sop_documents.id", ondelete="CASCADE"),
                          nullable=False)
    group_id     = Column(String(100), nullable=False, default="default")
    chunk_index  = Column(Integer, nullable=False)
    chunk_text   = Column(Text, nullable=False)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
```

> Note: `SopChunk` in server-api does **not** include the `embedding` column — server-api never writes embeddings (only the worker does). The column exists in the DB but not in the server-api ORM model.

- [ ] **Step 5: Add migration in server-api/app/main.py**

Inside `_migrate_alerts_columns()`, after the `case_embeddings` migration block (added in Task 2), add:

```python
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sop_documents (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                filename     VARCHAR(500) NOT NULL,
                content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
                raw_text     TEXT NOT NULL,
                status       VARCHAR(20) NOT NULL DEFAULT 'pending',
                uploaded_by  UUID REFERENCES users(id) ON DELETE SET NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sop_documents_group
            ON sop_documents(group_id)
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sop_chunks (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                document_id  UUID NOT NULL REFERENCES sop_documents(id) ON DELETE CASCADE,
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                chunk_index  INTEGER NOT NULL,
                chunk_text   TEXT NOT NULL,
                embedding    vector(384) NOT NULL,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sop_chunks_group
            ON sop_chunks(group_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_sop_chunks_ivfflat
            ON sop_chunks
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 10)
        """))
```

- [ ] **Step 6: Run test to verify it passes**

```bash
python -m pytest tests/test_rag.py::test_sop_models_have_required_fields -v
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add worker/worker/models.py server-api/app/models/models.py server-api/app/main.py worker/tests/test_rag.py
git commit -m "feat(sop): add sop_documents + sop_chunks tables and models"
```

---

## Task 8: Server-API — SOP upload endpoint + text extraction

**Files:**
- Modify: `server-api/requirements.txt`
- Modify: `server-api/app/schemas/schemas.py`
- Create: `server-api/app/api/routes/sop.py`
- Modify: `server-api/app/main.py` (register router)

- [ ] **Step 1: Add text extraction dependencies**

Append to `server-api/requirements.txt`:

```
pypdf>=4.0.0
python-docx>=1.1.0
```

- [ ] **Step 2: Add Pydantic schemas**

Open `server-api/app/schemas/schemas.py`. After the last schema class, add:

```python
class SopDocumentOut(BaseModel):
    id: UUID
    group_id: str
    filename: str
    content_type: str
    status: str
    uploaded_by: UUID | None
    created_at: datetime
    model_config = {"from_attributes": True}

class SopDocumentCreate(BaseModel):
    pass  # handled via multipart UploadFile — no JSON body needed
```

- [ ] **Step 3: Create server-api/app/api/routes/sop.py**

```python
# server-api/app/api/routes/sop.py
import io
import uuid
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user, get_db, get_scoped_group
from app.models.models import SopDocument
from app.schemas.schemas import SopDocumentOut

router = APIRouter(tags=["sop"])

ALLOWED_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
}
MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def _extract_text(content: bytes, content_type: str) -> str:
    if content_type == "application/pdf":
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(content))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    if content_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        import docx
        doc = docx.Document(io.BytesIO(content))
        return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
    return content.decode("utf-8", errors="replace")


@router.get("/api/sop-documents", response_model=list[SopDocumentOut])
async def list_sop_documents(
    db: AsyncSession = Depends(get_db),
    group_id: str = Depends(get_scoped_group),
    _=Depends(get_current_user),
):
    rows = (await db.execute(
        select(SopDocument)
        .where(SopDocument.group_id == group_id)
        .order_by(SopDocument.created_at.desc())
    )).scalars().all()
    return rows


@router.post("/api/sop-documents", response_model=SopDocumentOut, status_code=201)
async def upload_sop_document(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    group_id: str = Depends(get_scoped_group),
    current_user=Depends(get_current_user),
):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=415, detail=f"Unsupported file type: {file.content_type}. Use PDF, DOCX, or TXT.")
    content = await file.read()
    if len(content) > MAX_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large. Max 10 MB.")
    try:
        raw_text = _extract_text(content, file.content_type)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to extract text: {e}")
    if not raw_text.strip():
        raise HTTPException(status_code=422, detail="Document contains no extractable text.")

    doc = SopDocument(
        group_id=group_id,
        filename=file.filename or "document",
        content_type=file.content_type,
        raw_text=raw_text,
        status="pending",
        uploaded_by=current_user.id,
    )
    db.add(doc)
    await db.commit()
    await db.refresh(doc)
    return doc


@router.delete("/api/sop-documents/{doc_id}", status_code=204)
async def delete_sop_document(
    doc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    group_id: str = Depends(get_scoped_group),
    _=Depends(get_current_user),
):
    doc = await db.get(SopDocument, doc_id)
    if not doc or doc.group_id != group_id:
        raise HTTPException(status_code=404, detail="SOP document not found")
    await db.delete(doc)
    await db.commit()
```

- [ ] **Step 4: Register the router in server-api/app/main.py**

Open `server-api/app/main.py`. Find the block where other routers are registered (the `app.include_router(...)` calls). Add:

```python
from app.api.routes.sop import router as sop_router
```

at the top with the other route imports, then add:

```python
app.include_router(sop_router)
```

alongside the other `include_router` calls.

- [ ] **Step 5: Verify endpoint loads without errors**

```bash
cd /home/wonka/Documents/hackathon
docker compose up -d --build server-api
docker compose logs server-api 2>/dev/null | grep -E "error|Error|sop" | head -10
```

Expected: no import errors; `docker compose logs server-api | grep "Application startup"` shows success.

- [ ] **Step 6: Commit**

```bash
git add server-api/requirements.txt server-api/app/schemas/schemas.py \
        server-api/app/api/routes/sop.py server-api/app/main.py
git commit -m "feat(sop): add SOP upload endpoint with PDF/DOCX/TXT text extraction"
```

---

## Task 9: Worker — SOP chunking + embedding background loop

**Files:**
- Modify: `worker/worker/rag.py` (add `index_sop_document`, `retrieve_sop_context`)
- Modify: `worker/worker/rag_indexer.py` (add `sop_index_loop`)
- Modify: `worker/worker/main.py` (start `sop_index_loop`)

- [ ] **Step 1: Write failing tests**

Add to `worker/tests/test_rag.py`:

```python
def test_chunk_text_splits_correctly():
    from worker.rag import _chunk_text
    text = "Paragraph one.\n\nParagraph two.\n\nParagraph three."
    chunks = _chunk_text(text, max_chars=30)
    assert len(chunks) >= 2
    assert all(len(c) <= 30 for c in chunks)
    assert all(c.strip() for c in chunks)


def test_retrieve_sop_context_returns_list():
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

            from worker.rag import retrieve_sop_context
            result = await retrieve_sop_context("brute force incident response", "default")
            assert isinstance(result, list)

    asyncio.run(run())
```

- [ ] **Step 2: Run to verify they fail**

```bash
python -m pytest tests/test_rag.py -v -k "chunk or sop_context"
```

Expected: FAIL with `ImportError: cannot import name '_chunk_text'`

- [ ] **Step 3: Add chunking + SOP functions to worker/worker/rag.py**

Append to the end of `worker/worker/rag.py` (after the existing `retrieve_similar_cases` function):

```python
def _chunk_text(text: str, max_chars: int = 800) -> list[str]:
    """Split text into chunks at paragraph boundaries, max max_chars each."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 <= max_chars:
            current = f"{current}\n\n{para}".strip()
        else:
            if current:
                chunks.append(current)
            # if single paragraph exceeds max, split by sentence roughly
            if len(para) > max_chars:
                for i in range(0, len(para), max_chars):
                    chunks.append(para[i:i + max_chars])
            else:
                current = para
    if current:
        chunks.append(current)
    return chunks


async def index_sop_document(document_id: str, group_id: str, raw_text: str) -> None:
    """Chunk and embed a SOP document, insert into sop_chunks, mark document indexed."""
    chunks = _chunk_text(raw_text)
    if not chunks:
        log.warning("sop_empty_document", document_id=document_id)
        return

    rows = []
    for i, chunk in enumerate(chunks):
        try:
            vector = embed_text(chunk)
        except Exception as e:
            log.warning("sop_embed_chunk_failed", document_id=document_id, chunk=i, error=str(e))
            continue
        rows.append({
            "id": str(uuid.uuid4()),
            "document_id": document_id,
            "group_id": group_id,
            "chunk_index": i,
            "chunk_text": chunk,
            "embedding": str(vector),
        })

    try:
        async with AsyncSessionLocal() as db:
            for row in rows:
                await db.execute(text("""
                    INSERT INTO sop_chunks
                        (id, document_id, group_id, chunk_index, chunk_text, embedding)
                    VALUES
                        (:id, :document_id, :group_id, :chunk_index, :chunk_text, :embedding)
                    ON CONFLICT DO NOTHING
                """), row)
            await db.execute(text("""
                UPDATE sop_documents SET status = 'indexed', updated_at = now()
                WHERE id = :id
            """), {"id": document_id})
            await db.commit()
        log.info("sop_document_indexed", document_id=document_id, chunks=len(rows))
    except Exception as e:
        log.warning("sop_index_failed", document_id=document_id, error=str(e))
        async with AsyncSessionLocal() as db:
            await db.execute(text("""
                UPDATE sop_documents SET status = 'failed', updated_at = now()
                WHERE id = :id
            """), {"id": document_id})
            await db.commit()


async def retrieve_sop_context(
    query_text: str,
    group_id: str,
    top_k: int = 3,
    min_score: float = 0.55,
) -> list[str]:
    """
    Return top-k SOP chunk texts most relevant to query_text.
    Returns plain strings — injected directly into the prompt.
    """
    try:
        vector = embed_text(query_text)
    except Exception as e:
        log.warning("sop_embed_query_failed", error=str(e))
        return []

    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(text("""
                SELECT
                    sc.chunk_text,
                    sd.filename,
                    1 - (sc.embedding <=> :embedding::vector) AS similarity
                FROM sop_chunks sc
                JOIN sop_documents sd ON sd.id = sc.document_id
                WHERE sc.group_id = :group_id
                  AND sd.status = 'indexed'
                  AND 1 - (sc.embedding <=> :embedding::vector) >= :min_score
                ORDER BY sc.embedding <=> :embedding::vector
                LIMIT :top_k
            """), {
                "embedding": str(vector),
                "group_id": group_id,
                "min_score": min_score,
                "top_k": top_k,
            })).mappings().all()
            return [f"[{r['filename']}] {r['chunk_text']}" for r in rows]
    except Exception as e:
        log.warning("sop_retrieve_failed", error=str(e))
        return []
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_rag.py -v -k "chunk or sop_context"
```

Expected: both tests PASS

- [ ] **Step 5: Add sop_index_loop to worker/worker/rag_indexer.py**

Append at the end of `worker/worker/rag_indexer.py` (after the existing `rag_index_loop` function):

```python
SOP_INDEX_INTERVAL = 60  # poll every 60s for pending documents


async def sop_index_loop() -> None:
    await asyncio.sleep(90)  # stagger startup after rag_index_loop
    while True:
        try:
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(text("""
                    SELECT id::text, group_id, raw_text
                    FROM sop_documents
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT 10
                """))).mappings().all()

            for row in rows:
                await index_sop_document(
                    document_id=row["id"],
                    group_id=row["group_id"],
                    raw_text=row["raw_text"],
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("sop_indexer_error", error=str(e))

        await asyncio.sleep(SOP_INDEX_INTERVAL)
```

Also add the import at the top of `rag_indexer.py`:

```python
from worker.rag import index_case, index_sop_document
```

(replace the existing `from worker.rag import index_case` import)

- [ ] **Step 6: Start sop_index_loop in worker/worker/main.py**

In `worker/worker/main.py`, update the rag_indexer import:

```python
from worker.rag_indexer import rag_index_loop, sop_index_loop
```

Then add alongside the existing `rag_index_loop` task:

```python
asyncio.ensure_future(sop_index_loop())
```

- [ ] **Step 7: Run full test suite**

```bash
python -m pytest tests/test_rag.py -v
```

Expected: all tests PASS

- [ ] **Step 8: Commit**

```bash
git add worker/worker/rag.py worker/worker/rag_indexer.py worker/worker/main.py worker/tests/test_rag.py
git commit -m "feat(sop): worker SOP chunking + embedding loop + retrieve_sop_context"
```

---

## Task 10: Inject SOP context into Groq L1 triage prompt

**Files:**
- Modify: `worker/worker/groq_client.py` (`analyze_alert_with_groq`)
- Modify: `worker/worker/ai_analyst.py` (`analyze_and_maybe_create_case`)

- [ ] **Step 1: Write failing test**

Add to `worker/tests/test_rag.py`:

```python
def test_analyze_alert_accepts_sop_context_param():
    import inspect
    from worker.groq_client import analyze_alert_with_groq
    sig = inspect.signature(analyze_alert_with_groq)
    assert "sop_context" in sig.parameters
```

- [ ] **Step 2: Run to verify it fails**

```bash
python -m pytest tests/test_rag.py::test_analyze_alert_accepts_sop_context_param -v
```

Expected: FAIL with `AssertionError`

- [ ] **Step 3: Add sop_context param to analyze_alert_with_groq**

In `worker/worker/groq_client.py`, update the `analyze_alert_with_groq` signature (already has `similar_cases` from Task 5):

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
    sop_context: list[str] | None = None,
) -> dict:
```

After the `similar_cases_section` block (added in Task 5), add:

```python
    sop_section = ""
    if sop_context:
        lines = "\n\n".join(f"- {chunk}" for chunk in sop_context[:3])
        sop_section = f"\n\nSOP PERUSAHAAN — PANDUAN INSIDEN:\n{lines}"
```

Then add `{sop_section}` to the prompt f-string, after `{similar_cases_section}`:

```python
    prompt = f"""ALERT UNTUK DITRIAGE:
Title    : {title}
Severity : {severity}
Source IP: {source_ip or 'tidak diketahui'}
Hostname : {hostname or 'tidak diketahui'}
Fields   : {json.dumps(decoded_fields, default=str)[:500]}{ioc_list}{mitre_hint}{enrichment_section}{similar_cases_section}{sop_section}

Lakukan triage dan berikan verdict-mu sebagai analis L1."""
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_rag.py::test_analyze_alert_accepts_sop_context_param -v
```

Expected: PASS

- [ ] **Step 5: Call retrieve_sop_context in ai_analyst.py**

In `worker/worker/ai_analyst.py`, update the rag import at the top:

```python
from worker.rag import retrieve_similar_cases, retrieve_sop_context
```

In `analyze_and_maybe_create_case`, after the `retrieve_similar_cases` call (step `# ── 2b. RAG`), add:

```python
    # ── 2c. RAG — SOP perusahaan ────────────────────────────────────────────
    sop_context = await retrieve_sop_context(query_text, group_id)
    if sop_context:
        log.info("rag_sop_found", alert_id=alert_id, chunks=len(sop_context))
```

Pass `sop_context` to the Groq call:

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
        sop_context=sop_context if sop_context else None,
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
git commit -m "feat(sop): inject SOP context into Groq L1 triage prompt"
```

---

## Task 11: Frontend — SOP management page

**Files:**
- Create: `dashboard/src/pages/SopPage.tsx`
- Modify: `dashboard/src/App.tsx`
- Modify: `dashboard/src/components/Sidebar.tsx`

- [ ] **Step 1: Create dashboard/src/pages/SopPage.tsx**

```tsx
// dashboard/src/pages/SopPage.tsx
import { useRef, useState } from 'react'
import { format } from 'date-fns'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, FileText, Loader2 } from 'lucide-react'
import { api } from '@/api/client'

interface SopDocument {
  id: string
  filename: string
  content_type: string
  status: 'pending' | 'indexed' | 'failed'
  uploaded_by: string | null
  created_at: string
}

const statusColor = {
  pending:  'var(--accent-yellow)',
  indexed:  'var(--accent-green)',
  failed:   'var(--accent-red)',
}

export default function SopPage() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  const { data: docs = [], isLoading } = useQuery<SopDocument[]>({
    queryKey: ['sop-documents'],
    queryFn: () => api.get('/api/sop-documents').then(r => r.data),
    refetchInterval: 5000,  // poll to catch pending→indexed transitions
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/sop-documents/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sop-documents'] }),
  })

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setError('')
    setUploading(true)
    const form = new FormData()
    form.append('file', file)
    try {
      await api.post('/api/sop-documents', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      qc.invalidateQueries({ queryKey: ['sop-documents'] })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Upload failed')
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <h1 style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--text-primary)', margin: 0 }}>
          SOP Documents
        </h1>
        <div>
          <input ref={fileRef} type="file" accept=".pdf,.docx,.txt" style={{ display: 'none' }} onChange={handleUpload} />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={uploading}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '6px',
              padding: '8px 16px', borderRadius: '4px',
              border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.12)',
              color: 'var(--accent-cyan)', fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 700, fontSize: '12px', letterSpacing: '1px',
              cursor: uploading ? 'wait' : 'pointer', opacity: uploading ? 0.6 : 1,
            }}
          >
            {uploading ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}
            UPLOAD SOP
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: '4px', background: 'rgba(255,34,68,0.1)', border: '1px solid rgba(255,34,68,0.3)', color: 'var(--accent-red)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '12px' }}>
        Upload PDF, DOCX, or TXT files (max 10 MB). Uploaded SOPs are chunked, embedded, and used by the AI analyst when triaging alerts.
      </div>

      {isLoading ? (
        <div style={{ color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>Loading...</div>
      ) : docs.length === 0 ? (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', border: '1px dashed var(--border)', borderRadius: '6px' }}>
          No SOP documents uploaded yet. Upload your Incident Handling SOP to improve AI triage accuracy.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {docs.map(doc => (
            <div key={doc.id} style={{
              display: 'flex', alignItems: 'center', gap: '12px',
              padding: '12px 14px', borderRadius: '6px',
              border: '1px solid var(--border)', background: 'var(--bg-card)',
            }}>
              <FileText size={16} style={{ color: 'var(--accent-cyan)', flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {doc.filename}
                </div>
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {format(new Date(doc.created_at), 'yyyy-MM-dd HH:mm')} · {doc.content_type.split('/').pop()?.toUpperCase()}
                </div>
              </div>
              <span style={{
                padding: '2px 8px', borderRadius: '3px',
                border: `1px solid ${statusColor[doc.status]}44`,
                background: `${statusColor[doc.status]}18`,
                color: statusColor[doc.status],
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                fontSize: '10px', letterSpacing: '1px', textTransform: 'uppercase',
              }}>
                {doc.status}
              </span>
              <button
                onClick={() => deleteMutation.mutate(doc.id)}
                disabled={deleteMutation.isPending}
                style={{
                  padding: '4px 8px', borderRadius: '4px', border: '1px solid rgba(255,34,68,0.3)',
                  background: 'rgba(255,34,68,0.08)', color: 'var(--accent-red)',
                  cursor: 'pointer', display: 'flex', alignItems: 'center',
                }}
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Add route in dashboard/src/App.tsx**

Add the import with the other page imports:

```tsx
import SopPage from '@/pages/SopPage'
```

Add the route inside the `<Layout />` route block (minRole="analyst" — analysts upload SOPs):

```tsx
<Route path="/sop" element={<ProtectedRoute minRole="analyst"><SopPage /></ProtectedRoute>} />
```

- [ ] **Step 3: Add nav item in dashboard/src/components/Sidebar.tsx**

Find the nav items array. Add a SOP entry (import `BookMarked` from lucide-react alongside existing icon imports):

```tsx
{ to: '/sop', label: 'SOP Docs', icon: BookMarked, minRole: 'analyst' },
```

Place it after the `Handover` entry.

- [ ] **Step 4: Type-check**

```bash
cd /home/wonka/Documents/hackathon/dashboard
npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/pages/SopPage.tsx dashboard/src/App.tsx dashboard/src/components/Sidebar.tsx
git commit -m "feat(sop): add SOP management page — upload, list, delete"
```

---

## Task 12: Smoke test end-to-end

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

- [ ] **Step 6: Verify SOP upload + indexing**

Open the dashboard at `http://localhost` → navigate to **SOP Docs**. Upload a `.txt` file containing sample incident response steps. Within 60 seconds, status should change from `pending` → `indexed`.

```bash
docker compose logs -f worker | grep -E "sop_document_indexed|sop_indexer_error"
```

Expected: `{"event": "sop_document_indexed", "document_id": "...", "chunks": N}`

- [ ] **Step 7: Verify SOP context appears in alert triage**

Trigger a new alert. Watch worker logs:

```bash
docker compose logs -f worker | grep -E "rag_sop_found|rag_similar_found|ai_l1_triage_done"
```

Expected (once SOP is indexed and alert fires):
```
{"event": "rag_sop_found", "alert_id": "...", "chunks": 2}
{"event": "ai_l1_triage_done", "verdict": "...", ...}
```

- [ ] **Step 8: Final commit**

```bash
git add .
git commit -m "feat(rag): end-to-end RAG — similar cases + company SOP integrated"
```

---

## Self-Review

**Spec coverage:**
- ✅ pgvector infrastructure (Task 1)
- ✅ case_embeddings table + model (Task 2)
- ✅ embed_text + index_case + retrieve_similar_cases (Task 3)
- ✅ Background indexer for resolved cases (Task 4)
- ✅ Inject similar cases into Groq prompt (Task 5)
- ✅ sop_documents + sop_chunks tables + models (Task 7)
- ✅ Server-API upload endpoint PDF/DOCX/TXT (Task 8)
- ✅ Worker SOP chunking + embedding + sop_index_loop (Task 9)
- ✅ Inject SOP context into Groq prompt (Task 10)
- ✅ Frontend SOP management page (Task 11)
- ✅ Smoke test (Task 12)
- ✅ FastEmbed `BAAI/bge-small-en-v1.5`, 384 dims
- ✅ Top-3 retrieval, min 60% cosine similarity threshold

**No placeholders found.**

**Type consistency check:**
- `index_case(case_id: str, title: str, description: Optional[str], verdict: str, group_id: str)` — used consistently in Task 3 and Task 4
- `retrieve_similar_cases(query_text: str, group_id: str, top_k: int = 3, min_score: float = 0.60) -> list[dict]` — called in Task 5 with matching signature
- `similar_cases` passed as `list[dict] | None` from Task 5 ai_analyst call to groq_client — consistent
- `CaseEmbedding` model defined in Task 2, imported in rag.py via `from worker.models import CaseEmbedding` — actually rag.py uses raw SQL, not the ORM model, so no import needed there. Consistent.
