"""Tamper-evident audit log (docs/operations/audit-log.md).

The database does the work, so every writer is covered, including the
worker's raw INSERT (worker/webblock_auto.py):

- A BEFORE INSERT trigger numbers each row (seq) and chains it: hash =
  SHA-256 over the previous row's hash and every field of this row. It takes
  an advisory lock, so concurrent writers line up and the chain has no forks.
- Triggers refuse UPDATE, DELETE and TRUNCATE. Nothing in the platform needs
  to change or remove an audit row; the actor id is a plain column (no
  foreign key), so deleting a user does not touch the rows they left.
- Someone with the database owner's rights can still drop the triggers.
  verify() then finds the edit: a changed row no longer matches its hash, a
  removed row leaves a gap in seq and a broken prev_hash. Removing the newest
  rows breaks nothing, so the worker writes the newest (seq, hash) to
  Elasticsearch every few minutes (worker/audit_checkpoint.py), and verify()
  checks the database still holds that row unchanged.

Rows written before this existed have no seq and stay outside the chain."""
from __future__ import annotations

from sqlalchemy import text

GENESIS = "GENESIS"
LOCK_KEY = 7438001  # pg_advisory_xact_lock key that serialises audit inserts

COLUMNS = (
    "seq BIGINT",
    "prev_hash VARCHAR(64)",
    "hash VARCHAR(64)",
    "actor_name VARCHAR(255)",
    "ip_address VARCHAR(64)",
    "user_agent VARCHAR(512)",
    "outcome VARCHAR(20)",
    "request VARCHAR(300)",
)

# Every field, in a fixed order, joined with the ASCII unit separator. jsonb's
# text form is canonical (sorted keys, fixed spacing), and created_at goes in
# as integer microseconds so no time-zone or format setting changes the hash.
ROW_HASH_SQL = f"""
CREATE OR REPLACE FUNCTION audit_row_hash(r audit_logs) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT encode(sha256(convert_to(concat_ws(chr(31),
    r.seq::text, coalesce(r.prev_hash, ''), r.id::text, coalesce(r.actor_id::text, ''),
    coalesce(r.actor_name, ''), coalesce(r.group_id, ''), r.action, coalesce(r.resource_type, ''),
    coalesce(r.resource_id, ''), coalesce(r.detail, '{{}}'::jsonb)::text, coalesce(r.ip_address, ''),
    coalesce(r.user_agent, ''), coalesce(r.outcome, ''), coalesce(r.request, ''),
    (floor(extract(epoch from r.created_at) * 1000000))::bigint::text), 'UTF8')), 'hex')
$$;
"""

INSERT_TRIGGER_SQL = f"""
CREATE OR REPLACE FUNCTION audit_chain_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_seq BIGINT; last_hash TEXT;
BEGIN
  PERFORM pg_advisory_xact_lock({LOCK_KEY});
  IF NEW.created_at IS NULL THEN NEW.created_at := clock_timestamp(); END IF;
  IF NEW.detail IS NULL THEN NEW.detail := '{{}}'::jsonb; END IF;
  IF NEW.outcome IS NULL THEN NEW.outcome := 'success'; END IF;
  SELECT seq, hash INTO last_seq, last_hash FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1;
  NEW.seq := COALESCE(last_seq, 0) + 1;
  NEW.prev_hash := COALESCE(last_hash, '{GENESIS}');
  NEW.hash := audit_row_hash(NEW);
  RETURN NEW;
END $$;
"""

GUARD_SQL = """
CREATE OR REPLACE FUNCTION audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only: % refused', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
"""


async def ensure(conn) -> None:
    """Idempotent: columns, chain functions and triggers (run at startup)."""
    for col in COLUMNS:
        await conn.execute(text(f"ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS {col}"))
    await conn.execute(text("ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_id_fkey"))
    await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_logs_seq ON audit_logs (seq) WHERE seq IS NOT NULL"))
    await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_ip ON audit_logs (ip_address, created_at DESC)"))
    await conn.execute(text(ROW_HASH_SQL))
    await conn.execute(text(INSERT_TRIGGER_SQL))
    await conn.execute(text(GUARD_SQL))
    await conn.execute(text("DROP TRIGGER IF EXISTS audit_logs_chain ON audit_logs"))
    await conn.execute(text("CREATE TRIGGER audit_logs_chain BEFORE INSERT ON audit_logs "
                            "FOR EACH ROW EXECUTE FUNCTION audit_chain_insert()"))
    await conn.execute(text("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs"))
    await conn.execute(text("CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs "
                            "FOR EACH ROW EXECUTE FUNCTION audit_guard()"))
    await conn.execute(text("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs"))
    await conn.execute(text("CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
                            "FOR EACH STATEMENT EXECUTE FUNCTION audit_guard()"))


async def verify(db, checkpoint: dict | None = None, batch: int = 5000, max_problems: int = 20) -> dict:
    """Walk the whole chain. checkpoint is the newest {seq, hash} recorded
    outside the database; the chain must still hold it."""
    problems: list[dict] = []
    checked = 0
    prev_seq: int | None = None
    prev_hash: str | None = None
    first_seq: int | None = None
    while True:
        rows = (await db.execute(text(
            "SELECT seq, prev_hash, hash, audit_row_hash(a) AS calc FROM audit_logs a "
            "WHERE seq IS NOT NULL AND seq > :after ORDER BY seq LIMIT :n"),
            {"after": prev_seq or 0, "n": batch})).mappings().all()
        if not rows:
            break
        for r in rows:
            seq = int(r["seq"])
            if first_seq is None:
                first_seq = seq
                if seq != 1:
                    problems.append({"seq": seq, "problem": f"rows 1-{seq - 1} are missing"})
                elif r["prev_hash"] != GENESIS:
                    problems.append({"seq": seq, "problem": "the first row does not start the chain"})
            else:
                if seq != prev_seq + 1:
                    problems.append({"seq": seq, "problem": f"rows {prev_seq + 1}-{seq - 1} are missing"})
                if r["prev_hash"] != prev_hash:
                    problems.append({"seq": seq, "problem": "does not link to the row before it"})
            if r["hash"] != r["calc"]:
                problems.append({"seq": seq, "problem": "content changed after it was written"})
            prev_seq, prev_hash = seq, r["hash"]
            checked += 1
        if len(problems) >= max_problems:
            break
    anchor = None
    if checkpoint and checkpoint.get("seq"):
        cp_seq = int(checkpoint["seq"])
        row = (await db.execute(text("SELECT hash FROM audit_logs WHERE seq = :s"), {"s": cp_seq})).first()
        if row is None:
            problems.append({"seq": cp_seq, "problem": "a checkpointed row is gone (newest rows deleted)"})
            anchor = "missing"
        elif row[0] != checkpoint.get("hash"):
            problems.append({"seq": cp_seq, "problem": "differs from the checkpoint kept in Elasticsearch"})
            anchor = "mismatch"
        else:
            anchor = "ok"
    return {"ok": not problems, "checked": checked, "last_seq": prev_seq, "last_hash": prev_hash,
            "problems": problems[:max_problems], "checkpoint": {**(checkpoint or {}), "status": anchor}}
