# tests/server-api/test_dockerfile_worker_modules.py
"""server-api imports a few worker modules, and its image copies them one by
one. A module imported but not copied passes every test here (the tests see
the whole repo) and breaks in production: agent_health was missed and every
agent heartbeat returned 500."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _needed_files(module: str) -> set[str]:
    """worker.soar.graph -> {soar/graph, soar/__init__}; worker.x -> {x}."""
    parts = module.split(".")
    files = {"/".join(parts)}
    for i in range(1, len(parts)):
        files.add("/".join(parts[:i]) + "/__init__")
    return files


def test_every_imported_worker_module_is_copied_into_the_image():
    imported = set()
    for path in (ROOT / "server-api" / "app").rglob("*.py"):
        for mod in re.findall(r"^\s*(?:from|import) worker\.([\w.]+)", path.read_text(), re.M):
            imported |= _needed_files(mod)
    dockerfile = (ROOT / "server-api" / "Dockerfile").read_text()
    copied = set(re.findall(r"worker/worker/([\w/]+)\.py", dockerfile))
    assert imported, "expected server-api to import worker modules"
    assert imported <= copied, f"server-api/Dockerfile doesn't copy {sorted(imported - copied)}"
    # the build context is a whitelist: a copied file it doesn't let through fails the build
    ignore = (ROOT / "server-api" / "Dockerfile.dockerignore").read_text()
    allowed = set(re.findall(r"^!worker/worker/([\w/]+)\.py$", ignore, re.M))
    assert copied <= allowed, f"Dockerfile.dockerignore doesn't let through {sorted(copied - allowed)}"


def test_worker_subpackages_land_in_matching_directories():
    # COPY flattens its sources into the destination, so each subpackage needs its own line
    dockerfile = (ROOT / "server-api" / "Dockerfile").read_text()
    for line in re.findall(r"^COPY (worker/worker/.+)$", dockerfile, re.M):
        *sources, dest = line.split()
        dirs = {str(Path(s).parent).removeprefix("worker/worker").strip("/") for s in sources}
        assert len(dirs) == 1, f"one COPY mixes worker directories: {line}"
        assert dest.rstrip("/") == ("./worker/" + dirs.pop()).rstrip("/"), f"wrong destination: {line}"


def test_yaracheck_is_built_from_the_agent_engine_and_installed():
    # app/services/yara_capability.py runs `yaracheck`; without it AI YARA drafts can never activate
    dockerfile = (ROOT / "server-api" / "Dockerfile").read_text()
    assert "go build" in dockerfile and "./cmd/yaracheck" in dockerfile
    assert "COPY agent/internal/yara/" in dockerfile and "COPY agent/cmd/yaracheck/" in dockerfile
    assert re.search(r"^COPY --from=yaracheck \S+ /usr/local/bin/yaracheck$", dockerfile, re.M)
    ignore = (ROOT / "server-api" / "Dockerfile.dockerignore").read_text()
    for path in ("!agent/go.mod", "!agent/go.sum", "!agent/internal/yara", "!agent/cmd/yaracheck"):
        assert re.search(rf"^{re.escape(path)}$", ignore, re.M), f"Dockerfile.dockerignore must let through {path}"
    # the stage compiles only what the engine and the CLI import: the standard library
    for src in [*(ROOT / "agent/internal/yara").glob("*.go"), *(ROOT / "agent/cmd/yaracheck").glob("*.go")]:
        block = re.search(r"import \((.*?)\)|import (\"[^\"]+\")", src.read_text(), re.S)
        if src.name.endswith("_test.go") or block is None:  # some engine files import nothing
            continue
        for imp in re.findall(r'"([\w./-]+)"', block.group(0)):
            assert "." not in imp.split("/")[0] or imp.startswith("github.com/siem-platform/agent/internal/yara"), \
                f"{src.name} imports {imp}, which the yaracheck stage would have to download"
