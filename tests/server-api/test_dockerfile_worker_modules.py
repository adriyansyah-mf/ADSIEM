# tests/server-api/test_dockerfile_worker_modules.py
"""server-api imports a few worker modules, and its image copies them one by
one. A module imported but not copied passes every test here (the tests see
the whole repo) and breaks in production: agent_health was missed and every
agent heartbeat returned 500."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_every_imported_worker_module_is_copied_into_the_image():
    imported = set()
    for path in (ROOT / "server-api" / "app").rglob("*.py"):
        imported |= set(re.findall(r"^\s*(?:from|import) worker\.(\w+)", path.read_text(), re.M))
    dockerfile = (ROOT / "server-api" / "Dockerfile").read_text()
    copied = set(re.findall(r"worker/worker/(\w+)\.py", dockerfile))
    assert imported, "expected server-api to import worker modules"
    assert imported <= copied, f"server-api/Dockerfile doesn't copy {sorted(imported - copied)}"
    # the build context is a whitelist: a copied file it doesn't let through fails the build
    ignore = (ROOT / "server-api" / "Dockerfile.dockerignore").read_text()
    allowed = set(re.findall(r"^!worker/worker/(\w+)\.py$", ignore, re.M))
    assert copied <= allowed, f"Dockerfile.dockerignore doesn't let through {sorted(copied - allowed)}"
