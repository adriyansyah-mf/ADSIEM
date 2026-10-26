# server-api/app/services/yara_capability.py
"""The full-YARA capability (spec section 10.7): validation and scans with the
agents' own engine, through the `yaracheck` binary built from
agent/cmd/yaracheck and shipped in the server-api image. No compiler library
is imported into Python, and a rule that validates here compiles on every
endpoint running the same engine version.

Without the binary the capability reports itself unavailable and AI YARA
drafting stays in draft_only mode (services/yara_drafting.generation_mode).
"""
from __future__ import annotations

import asyncio
import json
import os
import resource
import shutil
import tempfile
import time

import structlog

log = structlog.get_logger()

TIMEOUT = 30            # seconds per yaracheck run
MEMORY_LIMIT = 1 << 30  # address space for a yaracheck run
CACHE_SECONDS = 60

_cache: tuple[float, dict] | None = None


class CapabilityError(RuntimeError):
    pass


def binary() -> str | None:
    path = os.environ.get("YARACHECK_PATH") or shutil.which("yaracheck")
    return path if path and os.access(path, os.X_OK) else None


def _limits() -> None:  # runs in the child before exec
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


async def run(*args: str, stdin: str | None = None) -> dict:
    """One yaracheck invocation → its JSON object. Raises CapabilityError when it can't run."""
    path = binary()
    if path is None:
        raise CapabilityError("yaracheck is not installed on this server")
    proc = await asyncio.create_subprocess_exec(
        path, *args, stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, preexec_fn=_limits)
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin.encode() if stdin is not None else None), TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise CapabilityError(f"yaracheck {args[0]} took longer than {TIMEOUT}s")
    try:
        data = json.loads(out.decode() or "{}")
    except ValueError:
        raise CapabilityError(f"yaracheck {args[0]} returned no JSON: {err.decode()[:300]}")
    if proc.returncode != 0:
        raise CapabilityError(data.get("error") or err.decode()[:300] or f"yaracheck exited {proc.returncode}")
    return data


async def capabilities() -> dict:
    """What the server can do with YARA rules right now (cached for a minute)."""
    global _cache
    if _cache is not None and time.monotonic() - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    try:
        engine = await run("capabilities")
        out = {"available": True, "validation": True, "endpoint_test": True, "server_test": False,
               "deployment": True, **engine,
               "notes": ["server-side tests need a governed sample store, which this platform does not have; "
                         "drafts are tested with rule-scoped scans on endpoints"]}
    except CapabilityError as exc:
        out = {"available": False, "validation": False, "endpoint_test": False, "server_test": False,
               "deployment": False, "error": str(exc)}
    _cache = (time.monotonic(), out)
    return out


def invalidate() -> None:
    global _cache
    _cache = None


async def validate(text: str) -> dict:
    """{"ok", "error", "line", "rules", "fingerprint", "engine_version"} for a rule text."""
    return await run("validate", stdin=text)


async def scan_files(text: str, paths: list[str]) -> dict:
    """Scan server-side files with one rule text (for a future governed sample store)."""
    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as f:
        f.write(text)
        rule_path = f.name
    try:
        return await run("scan", "-rules", rule_path, *paths)
    finally:
        os.unlink(rule_path)
