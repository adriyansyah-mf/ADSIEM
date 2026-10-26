# server-api/app/services/knowledge_schema.py
"""Startup migration for the knowledge base (called from app.main). A module
of its own so tests can create the schema without importing the whole app."""
from sqlalchemy import text

from app.core.database import engine


async def migrate_knowledge() -> None:
    """Knowledge base (analyst notes, PayloadsAllTheThings) chunks with embeddings,
    and HNSW instead of IVFFlat on every RAG table: IVFFlat built on an empty
    table has meaningless centroids and silently misses rows; HNSW needs no training."""
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS knowledge_chunks (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                entry_id     UUID NOT NULL REFERENCES knowledge_entries(id) ON DELETE CASCADE,
                group_id     VARCHAR(100) NOT NULL DEFAULT 'default',
                kind         VARCHAR(20) NOT NULL,
                chunk_index  INTEGER NOT NULL,
                chunk_text   TEXT NOT NULL,
                embedding    vector(384) NOT NULL
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_entry ON knowledge_chunks(entry_id)"))
        # Knowledge vault: article columns on databases created before them (fresh ones get them from the model)
        for col in ("slug VARCHAR(200)", "path TEXT", "tags JSONB NOT NULL DEFAULT '[]'::jsonb",
                    "frontmatter JSONB NOT NULL DEFAULT '{}'::jsonb", "status VARCHAR(20) NOT NULL DEFAULT 'published'",
                    "trust VARCHAR(20) NOT NULL DEFAULT 'reviewed'",
                    "content_type VARCHAR(30) NOT NULL DEFAULT 'environment'", "owner_id UUID", "reviewed_by UUID",
                    "reviewed_at TIMESTAMPTZ", "version INTEGER NOT NULL DEFAULT 1", "checksum VARCHAR(64)",
                    "index_error TEXT"):
            await conn.execute(text(f"ALTER TABLE knowledge_entries ADD COLUMN IF NOT EXISTS {col}"))
        # synced reference material is external, whatever the column default said when it was added
        await conn.execute(text("UPDATE knowledge_entries SET trust = 'external', content_type = 'external_reference' "
                                "WHERE kind = 'reference' AND trust <> 'external'"))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_knowledge_entries_slug "
                                "ON knowledge_entries(group_id, slug) WHERE slug IS NOT NULL"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_knowledge_entries_path ON knowledge_entries(group_id, path)"))
        # heading-aware chunks with a full-text vector next to the embedding (hybrid retrieval)
        await conn.execute(text("ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS heading TEXT"))
        await conn.execute(text(
            "ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS tsv tsvector GENERATED ALWAYS AS "
            "(to_tsvector('simple', coalesce(heading, '') || ' ' || chunk_text)) STORED"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_tsv ON knowledge_chunks USING gin (tsv)"))
        for table in ("knowledge_chunks", "case_embeddings", "sop_chunks", "feedback_embeddings"):
            if not (await conn.execute(text(
                "SELECT 1 FROM information_schema.columns WHERE table_name = :t AND column_name = 'embedding'"
            ), {"t": table})).first():
                continue
            await conn.execute(text(f"DROP INDEX IF EXISTS idx_{table}_ivfflat"))
            await conn.execute(text(
                f"CREATE INDEX IF NOT EXISTS idx_{table}_hnsw ON {table} USING hnsw (embedding vector_cosine_ops)"))
