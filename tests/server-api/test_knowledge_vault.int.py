# tests/server-api/test_knowledge_vault.int.py
"""Knowledge vault API against a real Postgres: articles with revisions and
[[wikilinks]], what a save refuses, review rules, and the one-way Obsidian
import. Needs TEST_DATABASE_URL = DATABASE_URL."""
import asyncio
import io
import os
import uuid
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
                                reason="needs TEST_DATABASE_URL (= DATABASE_URL), Postgres with pgvector")

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import Base, engine
    from app.services.knowledge_schema import migrate_knowledge
    import app.models.models  # noqa: F401

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)
        await migrate_knowledge()
    _run(setup())
    yield
    _run(engine.dispose())


def _user(name, perms=("cases:manage",), group="blue"):
    """A real users row (articles reference their author), seen by routes as a role with permissions."""
    from app.core.database import AsyncSessionLocal
    from app.models.models import Role, User

    async def go():
        async with AsyncSessionLocal() as db:
            role = Role(name=f"{name}-{uuid.uuid4().hex[:6]}")
            db.add(role)
            await db.flush()
            user = User(username=f"{name}-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex}@x", password_hash="x",
                        role_id=role.id, group_id=group)
            db.add(user)
            await db.commit()
            return user.id
    return SimpleNamespace(id=_run(go()), username=name, group_id=group,
                           role=SimpleNamespace(name=name, permissions=[SimpleNamespace(name=p) for p in perms]))


@pytest.fixture(scope="module")
def people(env):
    return SimpleNamespace(ana=_user("ana"), bob=_user("bob"), lead=_user("lead", ("cases:manage", "settings:manage")))


def _call(fn, *args, group="blue", **kwargs):
    from app.core.database import AsyncSessionLocal

    async def go():
        async with AsyncSessionLocal() as db:
            return await fn(*args, db=db, group_filter=group, **kwargs)
    return _run(go())


def _refused(fn, *args, **kwargs):
    try:
        _call(fn, *args, **kwargs)
    except HTTPException as exc:
        return exc
    raise AssertionError("expected the call to be refused")


def _create(markdown, user, status=None, **kw):
    from app.api.routes import knowledge as k
    return _call(k.create_article, k.ArticleIn(markdown=markdown, status=status), BackgroundTasks(), user=user, **kw)


def test_articles_keep_revisions_links_and_backlinks(people):
    from app.api.routes import knowledge as k

    ANA = people.ana

    target = _create("# PowerShell Script Block Logging\n\nEvent 4104 holds the script text.", ANA, status="published")
    a = _create("---\ntitle: Investigating PowerShell\ntags: [windows, dfir]\nmitre: [T1059.001]\n---\n"
                "# Triage\n\nRead [[PowerShell Script Block Logging#4104]] first, then [[Parent Process]].\n", ANA)
    assert (a.status, a.trust, a.version, a.slug) == ("draft", "draft", 1, "investigating-powershell")
    assert a.tags == ["windows", "dfir"] and [h["text"] for h in a.headings] == ["Triage"]
    links = {link["target"]: link for link in a.outgoing}
    assert links["PowerShell Script Block Logging"]["entry_id"] == str(target.id)
    assert links["PowerShell Script Block Logging"]["heading"] == "4104"
    assert links["Parent Process"]["resolved"] is False

    back = _call(k.get_article, target.id, _=ANA)
    assert [b["entry_id"] for b in back.backlinks] == [str(a.id)]
    later = _create("# Parent Process\n\nWhich process started it.", ANA, status="published")
    resolved = {link["target"]: link for link in _call(k.get_article, a.id, _=ANA).outgoing}
    assert resolved["Parent Process"]["entry_id"] == str(later.id)  # a dangling link resolves once its note exists

    v2 = _call(k.update_article, a.id, k.ArticleIn(markdown=a.markdown + "\n## Containment\nIsolate.\n"),
               BackgroundTasks(), user=ANA)
    assert v2.version == 2
    same = _call(k.update_article, a.id, k.ArticleIn(markdown=v2.markdown), BackgroundTasks(), user=ANA)
    assert same.version == 2  # unchanged content makes no revision
    revisions = _call(k.article_revisions, a.id, _=ANA)
    assert [r["version"] for r in revisions] == [2, 1]
    restored = _call(k.restore_revision, a.id, 1, BackgroundTasks(), user=ANA)
    assert restored.version == 3 and "Containment" not in restored.markdown
    assert _call(k.article_revisions, a.id, _=ANA)[0]["note"] == "restored version 1"

    assert _call(k.publish_article, a.id, BackgroundTasks(), user=ANA).status == "published"
    assert _call(k.archive_article, a.id, BackgroundTasks(), user=ANA).status == "archived"
    assert _refused(k.get_article, a.id, _=ANA, group="red").status_code == 404
    titles = _call(k.article_titles, _=ANA, q="parent")
    assert [t["title"] for t in titles] == ["Parent Process"]


def test_saves_refuse_bad_frontmatter_secrets_and_other_groups(people):
    from app.api.routes import knowledge as k

    ANA, BOB, REVIEWER = people.ana, people.bob, people.lead

    bad = _refused(k.create_article, k.ArticleIn(markdown="---\nmitre: [T59]\n---\n# X"), BackgroundTasks(), user=ANA)
    assert bad.status_code == 422 and "mitre ids" in bad.detail["problems"][0]
    secret = _refused(k.create_article, k.ArticleIn(markdown="# Creds\naws AKIAABCDEFGHIJKLMNOP"), BackgroundTasks(),
                      user=ANA)
    assert "credentials" in secret.detail["message"] and "AKIAABCDEFGHIJKLMNOP" not in str(secret.detail)
    other = _refused(k.create_article, k.ArticleIn(markdown="---\nscope:\n  groups: [red]\n---\n# X"),
                     BackgroundTasks(), user=ANA)
    assert "your own group" in other.detail["message"]
    verified = _refused(k.create_article, k.ArticleIn(markdown="---\ntrust: verified\n---\n# Gospel"),
                        BackgroundTasks(), user=ANA)
    assert "knowledge reviewer" in verified.detail["message"]
    note_secret = _refused(k.create_note, k.NoteIn(title="db creds", content="password: Xk92mLpQ7rT4vW8yZ1aB3cD5"),
                           BackgroundTasks(), user=ANA)
    assert note_secret.status_code == 422

    article = _create("# Lateral movement via WMI\n\nWatch WmiPrvSE children.", ANA)
    assert _refused(k.review_article, article.id, k.ReviewIn(), BackgroundTasks(),
                    user=ANA).status_code == 409  # the author doesn't review their own
    reviewed = _call(k.review_article, article.id, k.ReviewIn(), BackgroundTasks(), user=BOB)
    assert reviewed.trust == "reviewed" and reviewed.reviewed_by == BOB.id
    assert _refused(k.review_article, article.id, k.ReviewIn(trust="verified"), BackgroundTasks(),
                    user=BOB).status_code == 403
    assert _call(k.review_article, article.id, k.ReviewIn(trust="verified"), BackgroundTasks(),
                 user=REVIEWER).trust == "verified"


def _zip(files: dict, root="MyVault") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(f"{root}/{name}" if root else name, content)
    return buf.getvalue()


def _import(data, user, dry_run=True, publish=False, group="blue"):
    from app.api.routes import knowledge as k
    upload = SimpleNamespace(filename="vault.zip", read=lambda n=-1: _async(data))
    return _call(k.import_vault, BackgroundTasks(), user=user, file=upload, dry_run=dry_run, publish=publish,
                 group=group)


async def _async(value):
    return value


def test_obsidian_import_dry_runs_then_applies_only_changes(people):
    from sqlalchemy import func, select

    from app.api.routes import knowledge as k
    from app.core.database import AsyncSessionLocal
    from app.models.models import KnowledgeEntry

    vault_files = {
        "Lateral/WMI.md": "---\ntags: [windows]\n---\n# WMI\n\nSee [[Process Trees]] and [[Nowhere]].",
        "Process Trees.md": "# Process Trees\n\nParent-child chains.",
        "Broken.md": "---\nmitre: [nope]\n---\n# Broken",
        ".obsidian/workspace.json": "{}",
        "attachments/diagram.png": "PNG",
    }
    group = f"vault-{uuid.uuid4().hex[:6]}"
    user = _user("importer", group=group)

    async def count():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(func.count()).select_from(KnowledgeEntry)
                                     .where(KnowledgeEntry.group_id == group))).scalar_one()

    dry = _import(_zip(vault_files), user, group=group)
    assert dry["dry_run"] and sorted(dry["added"]) == ["Lateral/WMI.md", "Process Trees.md"]  # vault root stripped
    assert [e["path"] for e in dry["errors"]] == ["Broken.md"] and "mitre" in dry["errors"][0]["problems"][0]
    assert dry["skipped"] == [{"path": "attachments/diagram.png", "reason": "not a Markdown note"}]
    assert dry["unresolved_links"] == [{"path": "Lateral/WMI.md", "target": "Nowhere"}]
    assert _run(count()) == 0  # a dry run writes nothing

    applied = _import(_zip(vault_files), user, dry_run=False, publish=True, group=group)
    assert sorted(applied["added"]) == ["Lateral/WMI.md", "Process Trees.md"] and _run(count()) == 2
    wmi = next(a for a in _call(k.list_articles, _=user, group=group) if a.path == "Lateral/WMI.md")
    detail = _call(k.get_article, wmi.id, _=user, group=group)
    assert detail.status == "published" and detail.slug == "wmi"
    assert {link["target"]: link["resolved"] for link in detail.outgoing} == {"Process Trees": True, "Nowhere": False}

    again = _import(_zip(vault_files), user, dry_run=False, publish=True, group=group)
    assert again["added"] == [] and again["updated"] == [] and sorted(again["unchanged"]) == [
        "Lateral/WMI.md", "Process Trees.md"]
    changed = {**vault_files, "Process Trees.md": "# Process Trees\n\nParent-child chains, now with PPID spoofing."}
    third = _import(_zip(changed), user, dry_run=False, publish=True, group=group)
    assert third["updated"] == ["Process Trees.md"] and third["unchanged"] == ["Lateral/WMI.md"]


def test_import_refuses_traversal_and_zip_bombs(people):
    traversal = _zip({"../escape.md": "# Escape"}, root="")
    exc = None
    try:
        _import(traversal, people.ana)
    except HTTPException as e:
        exc = e
    assert exc is not None and "outside the vault" in exc.detail["message"]

    bomb = _zip({"huge.md": "0" * (30 << 20)})
    try:
        _import(bomb, people.ana)
        raise AssertionError("expected a refusal")
    except HTTPException as e:
        assert "expands too much" in e.detail["message"]
