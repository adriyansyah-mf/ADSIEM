# worker/worker/es_snapshots.py
"""Elasticsearch snapshots via its own snapshot lifecycle management (SLM).

Elasticsearch takes, schedules and expires the snapshots itself. The worker
only makes sure the filesystem repository and the policy exist (at startup and
on every maintenance run, so a recreated cluster heals itself). The repository
directory is path.repo in docker-compose.yml, a bind mount next to the Postgres
dumps (BACKUP_DIR). Restore: docs/operations/backup-restore.md."""
from __future__ import annotations

import os
from datetime import datetime, timezone

import structlog

log = structlog.get_logger()

REPOSITORY = "adsiem-backups"
POLICY = "adsiem-daily"
REPOSITORY_PATH = os.environ.get("ES_SNAPSHOT_PATH", "/usr/share/elasticsearch/snapshots")
SCHEDULE = os.environ.get("ES_SNAPSHOT_SCHEDULE", "0 30 1 * * ?")  # 01:30 UTC daily, before retention runs
RETAIN_DAYS = int(os.environ.get("ES_SNAPSHOT_RETAIN_DAYS", "14"))
INDICES = ["logs", "alert_iocs"]


def policy_body() -> dict:
    return {
        "schedule": SCHEDULE,
        "name": "<adsiem-{now/d}>",
        "repository": REPOSITORY,
        "config": {"indices": INDICES, "ignore_unavailable": True, "include_global_state": False},
        "retention": {"expire_after": f"{RETAIN_DAYS}d", "min_count": 3, "max_count": RETAIN_DAYS * 2},
    }


async def ensure(client) -> bool:
    """Create or update the repository and the SLM policy. Returns False (and
    logs why) when snapshots aren't configured, e.g. path.repo isn't set."""
    if os.environ.get("ES_SNAPSHOTS", "on").lower() in ("off", "0", "false"):
        return False
    resp = await client.put(f"/_snapshot/{REPOSITORY}",
                            json={"type": "fs", "settings": {"location": REPOSITORY_PATH, "compress": True}})
    if resp.status_code not in (200, 201):
        log.warning("es_snapshot_repository_unavailable", status=resp.status_code, body=resp.text[:300],
                    hint="set path.repo on elasticsearch and mount BACKUP_DIR (docs/operations/backup-restore.md)")
        return False
    resp = await client.put(f"/_slm/policy/{POLICY}", json=policy_body())
    if resp.status_code not in (200, 201):
        log.warning("es_snapshot_policy_failed", status=resp.status_code, body=resp.text[:300])
        return False
    return True


async def last_status(client) -> dict:
    """{"last_success": iso|None, "last_failure": iso|None} for the policy."""
    resp = await client.get(f"/_slm/policy/{POLICY}")
    if resp.status_code != 200:
        return {"last_success": None, "last_failure": None}
    info = resp.json().get(POLICY, {})
    return {"last_success": _when(info.get("last_success")), "last_failure": _when(info.get("last_failure"))}


def _when(entry: dict | None) -> str | None:
    """SLM reports `time` as epoch milliseconds (8.x) and sometimes `time_string`."""
    if not entry:
        return None
    if entry.get("time_string"):
        return entry["time_string"]
    millis = entry.get("time")
    if isinstance(millis, (int, float)):
        return datetime.fromtimestamp(millis / 1000, tz=timezone.utc).isoformat()
    return None
