"""AI skills (services/ai_skills.py, routes/ai_skills.py): built-in skills
synced from skills/*.md, analysts' own skills, and what the API allows."""
import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.api.routes import ai_skills as routes
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.models import AiSkill
from app.services import ai_skills

REPO_SKILLS = Path(__file__).resolve().parents[2] / "skills"
MANAGE = ("alerts:read", "settings:manage")


@pytest.fixture(autouse=True)
def _current_event_loop(event_loop):
    asyncio.set_event_loop(event_loop)
    yield


def _skill(name, description="Use it when the case is about something specific.", body="# Steps\n1. Check it."):
    return f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n"


@pytest.fixture
async def env(evidence_api, monkeypatch, tmp_path):
    async def database():
        async with evidence_api.sessions() as db:
            yield db

    audits = []

    async def audit(db, actor_id, action, resource_type=None, resource_id=None, detail=None, **kwargs):
        audits.append((action, detail))

    monkeypatch.setattr(routes, "audit_log", audit)
    monkeypatch.setenv("AI_SKILLS_DIR", str(tmp_path))
    evidence_api.skill_dir = tmp_path
    evidence_api.audit_calls = audits
    evidence_api.user = evidence_api.make_user(perms=MANAGE)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_current_user] = lambda: evidence_api.user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        evidence_api.api = client
        yield evidence_api


async def _rows(env):
    async with env.sessions() as db:
        return {r.name: r for r in (await db.execute(select(AiSkill))).scalars().all()}


def test_the_shipped_skills_parse():
    pack = {p.stem: ai_skills.parse_skill(p.read_text()) for p in REPO_SKILLS.glob("*.md")}
    assert len(pack) >= 6 and all(pack.values()), [k for k, v in pack.items() if not v]
    for stem, skill in pack.items():
        assert skill["name"] == stem and ai_skills.NAME_RE.match(skill["name"])
        assert len(skill["description"]) > 40 and len(skill["content"]) > 400
    assert "ot-ics-attack-investigation" in pack and "webshell-investigation" in pack


def test_the_shipped_skills_name_only_artifacts_and_tools_that_exist():
    """A skill that names a missing artifact or tool sends the investigator down a dead end."""
    import re

    from app.services.assistant_tools import TOOLS
    from app.services.flow_artifacts import builtin_artifacts
    from app.services.investigator import READ_ONLY_TOOLS

    artifacts = set(builtin_artifacts())
    tools = {t["name"] for t in TOOLS} | READ_ONLY_TOOLS | {
        "list_hosts", "list_artifacts", "run_artifact", "get_flow_rows", "record_hypothesis", "create_artifact",
        "lookup_malwarebazaar", "load_skill", "run_command"}
    # backticked snake_case words are tool names, except these log types, files and commands
    not_tools = {"log_type", "linux_auth", "linux_process_exec", "siem_agent", "project_scan", "nginx_access",
                 "apache_access", "authorized_keys", "information_schema", "pam_unix", "pg_dump"}
    problems = []
    for path in REPO_SKILLS.glob("*.md"):
        text = path.read_text()
        for art in re.findall(r"\b((?:Linux|Windows|Generic)\.[A-Za-z]+\.[A-Za-z]+)\b", text):
            if art not in artifacts:
                problems.append(f"{path.name}: artifact {art}")
        for name in re.findall(r"`([a-z]+(?:_[a-z]+)+)`", text):
            if name not in tools and name not in not_tools:
                problems.append(f"{path.name}: tool {name}")
    assert problems == []


async def test_sync_adds_updates_keeps_toggles_and_leaves_custom_alone(env):
    (env.skill_dir / "a.md").write_text(_skill("alpha-skill", body="# v1"))
    (env.skill_dir / "b.md").write_text(_skill("beta-skill"))
    assert await ai_skills.sync_builtin_skills(env.sessions) == {"added": 2, "updated": 0, "removed": 0}
    async with env.sessions() as db:
        db.add(AiSkill(name="mine", description="my own procedure for phishing", content="# mine", origin="custom"))
        (await db.execute(select(AiSkill).where(AiSkill.name == "beta-skill"))).scalar_one().is_enabled = False
        await db.commit()

    (env.skill_dir / "a.md").write_text(_skill("alpha-skill", body="# v2"))
    (env.skill_dir / "b.md").unlink()
    assert await ai_skills.sync_builtin_skills(env.sessions) == {"added": 0, "updated": 1, "removed": 1}
    rows = await _rows(env)
    assert rows["alpha-skill"].content == "# v2" and rows["alpha-skill"].origin == "builtin"
    assert "beta-skill" not in rows and rows["mine"].content == "# mine"

    (env.skill_dir / "b.md").write_text(_skill("beta-skill"))
    await ai_skills.sync_builtin_skills(env.sessions)
    async with env.sessions() as db:  # an analyst turns a built-in skill off; the next start keeps it off
        (await db.execute(select(AiSkill).where(AiSkill.name == "beta-skill"))).scalar_one().is_enabled = False
        await db.commit()
    (env.skill_dir / "b.md").write_text(_skill("beta-skill", body="# newer"))
    await ai_skills.sync_builtin_skills(env.sessions)
    beta = (await _rows(env))["beta-skill"]
    assert beta.content == "# newer" and beta.is_enabled is False


async def test_a_bad_file_is_skipped(env):
    (env.skill_dir / "bad.md").write_text("no frontmatter here")
    (env.skill_dir / "Bad Name.md").write_text(_skill("Bad Name"))
    assert ai_skills.load_pack() == []


async def test_catalog_lists_only_enabled_skills(env):
    async with env.sessions() as db:
        db.add_all([AiSkill(name="on-skill", description="use when on", content="x" * 30, origin="custom"),
                    AiSkill(name="off-skill", description="use when off", content="x" * 30, origin="custom",
                            is_enabled=False)])
        await db.commit()
        listed = await ai_skills.catalog(db)
        assert ("on-skill", "use when on") in listed and all(n != "off-skill" for n, _ in listed)
        assert (await ai_skills.get_enabled(db, "OFF-skill ")) is None
        assert (await ai_skills.get_enabled(db, " On-Skill")).name == "on-skill"
    prompt = ai_skills.catalog_prompt([("on-skill", "use when on")])
    assert "load_skill" in prompt and "- on-skill: use when on" in prompt
    assert ai_skills.catalog_prompt([]) == ""


async def test_api_create_edit_toggle_delete(env):
    body = {"name": "Phishing-Investigation", "description": "A user reported or clicked a phishing email.",
            "content": "# Phishing\n1. Find every recipient.\n2. Check clicks."}
    r = await env.api.post("/api/ai-skills", json=body)
    assert r.status_code == 201, r.text
    skill = r.json()
    assert skill["name"] == "phishing-investigation" and skill["origin"] == "custom" and skill["is_enabled"]
    assert (await env.api.post("/api/ai-skills", json=body)).status_code == 409
    assert (await env.api.post("/api/ai-skills", json={**body, "name": "no spaces allowed"})).status_code == 422

    r = await env.api.patch(f"/api/ai-skills/{skill['id']}", json={"content": "# Phishing v2\n1. Recipients first."})
    assert r.status_code == 200 and r.json()["content"].startswith("# Phishing v2")
    assert (await env.api.patch(f"/api/ai-skills/{skill['id']}", json={"is_enabled": False})).json()["is_enabled"] is False
    assert (await env.api.delete(f"/api/ai-skills/{skill['id']}")).status_code == 204
    assert [a for a, _ in env.audit_calls] == ["ai_skill.create", "ai_skill.update", "ai_skill.update", "ai_skill.delete"]


async def test_a_builtin_skill_can_be_turned_off_but_not_edited_or_deleted(env):
    (env.skill_dir / "w.md").write_text(_skill("webshell-investigation"))
    await ai_skills.sync_builtin_skills(env.sessions)
    builtin = next(s for s in (await env.api.get("/api/ai-skills")).json() if s["name"] == "webshell-investigation")
    assert builtin["origin"] == "builtin"
    edit = await env.api.patch(f"/api/ai-skills/{builtin['id']}", json={"content": "# changed in place, lost later"})
    assert edit.status_code == 409 and "save a copy" in edit.json()["detail"]
    assert (await env.api.patch(f"/api/ai-skills/{builtin['id']}", json={"is_enabled": False})).json()["is_enabled"] is False
    assert (await env.api.delete(f"/api/ai-skills/{builtin['id']}")).status_code == 409


async def test_analysts_read_and_only_managers_change(env):
    env.user = env.make_user(perms=("alerts:read",))
    assert (await env.api.get("/api/ai-skills")).status_code == 200
    r = await env.api.post("/api/ai-skills", json={"name": "x-skill", "description": "use it when x happens",
                                                   "content": "# X\n1. do the x check."})
    assert r.status_code == 403
