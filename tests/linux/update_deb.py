"""Self-update through systemd on a real Linux host (CI: ubuntu-latest, as root).

Both .debs are built trusting the same update key and signed with
siem-update-sign; tests/windows/mock_siem.py offers them like server-api's
rollout. Install --old -> an offer signed by an unknown key is refused (nothing
downloaded) -> the signed --new offer upgrades the running service through
dpkg in a transient unit -> offering --old again rolls back (a dpkg downgrade)
-> purge.

    sudo python3 tests/linux/update_deb.py --old OLD.deb --new NEW.deb --signer siem-update-sign
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PORT = 18091
CONFIG = Path("/etc/siem-agent/config.yaml")
STATE = Path("/var/lib/siem-agent/update/state.json")


def run(*argv, check=True, env=None):
    print("+", " ".join(map(str, argv)), flush=True)
    return subprocess.run([str(a) for a in argv], check=check, text=True, capture_output=True,
                          env={**os.environ, **(env or {})})


def version_of(deb: Path) -> str:
    return re.match(r"^siem-agent_([^_]+)_", deb.name).group(1)


class Mock:
    def __init__(self, work: Path, pkgs: Path):
        self.out = work / "mock"
        self.out.mkdir(parents=True)
        self.proc = subprocess.Popen([sys.executable, str(REPO / "tests/windows/mock_siem.py"), str(PORT), str(self.out)],
                                     env={**os.environ, "MOCK_UPDATE_DIR": str(pkgs),
                                          "MOCK_SOURCES": json.dumps([])})
        time.sleep(2)

    def heartbeats(self) -> list[dict]:
        f = self.out / "heartbeats.jsonl"
        return [json.loads(line) for line in f.read_text().splitlines()] if f.exists() else []

    def wait(self, cond, after: int, seconds: int, what: str) -> dict:
        deadline = time.time() + seconds
        while time.time() < deadline:
            for hb in self.heartbeats()[after:]:
                if cond(hb):
                    return hb
            time.sleep(2)
        fail(f"timed out waiting for {what}")

    def offer(self, deb: Path, revision: int, sig: Path | None = None):
        signed = json.loads((sig or Path(str(deb) + ".sig")).read_text())
        (self.out / "update_offer.json").write_text(json.dumps({
            "version": version_of(deb), "revision": revision,
            "url": f"/api/agent/update/package/{deb.name}", "signed": signed}))


def diagnostics():
    for title, argv in (("journal", ["journalctl", "-u", "siem-agent", "-n", "80", "--no-pager"]),
                        ("update units", ["journalctl", "-u", "siem-agent-update-*", "-n", "40", "--no-pager"])):
        print(f"---- {title}")
        print(run(*argv, check=False).stdout)
    for f in (STATE, STATE.with_name("install.log")):
        print(f"---- {f}")
        print(f.read_text() if f.exists() else "(missing)")
    if MOCK:
        print("---- last heartbeats")
        for hb in MOCK.heartbeats()[-3:]:
            print(json.dumps(hb)[:600])


def fail(msg: str):
    diagnostics()
    raise SystemExit(f"UPDATE TEST FAILED: {msg}")


def installed_version() -> str:
    return run("dpkg-query", "-W", "-f=${Version}", "siem-agent").stdout.strip()


MOCK: Mock | None = None


def main():
    global MOCK
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", type=Path, required=True)
    ap.add_argument("--new", type=Path, required=True)
    ap.add_argument("--signer", type=Path, required=True)
    a = ap.parse_args()
    old, new, signer = a.old.resolve(), a.new.resolve(), a.signer.resolve()
    work = Path(tempfile.mkdtemp(prefix="siem-update-"))
    pkgs = work / "packages"
    pkgs.mkdir()
    for f in (old, new):
        shutil.copy(f, pkgs)
        shutil.copy(str(f) + ".sig", pkgs)
    MOCK = mock = Mock(work, pkgs)
    try:
        run("dpkg", "-i", old)
        CONFIG.write_text(CONFIG.read_text().replace("heartbeat_interval: 30", "heartbeat_interval: 5"))
        run("siem-agent-configure", "--server", f"http://127.0.0.1:{PORT}", "--key", "ci-update-key-123",
            "--name", "ci-linux")
        hb = mock.wait(lambda h: h.get("version") == version_of(old) and (h.get("update") or {}).get("kind") == "deb"
                       and h["update"]["state"] == "idle", 0, 90, f"{version_of(old)} reporting a deb install")
        print(f"ok: {version_of(old)} installed, self-update ready ({hb['update']})")

        # 1. signed by a key the agent does not trust: refused before any download
        rogue = work / "rogue"
        rogue.mkdir()
        run(signer, "keygen", "-out", rogue / "key")
        shutil.copy(new, rogue)
        run(signer, "sign", "-key", rogue / "key", rogue / new.name)
        seen = len(mock.heartbeats())
        mock.offer(new, 1, rogue / (new.name + ".sig"))
        hb = mock.wait(lambda h: (h.get("update") or {}).get("state") == "failed" and h["update"]["revision"] == 1,
                       seen, 60, "the rogue offer to fail")
        if "trusted update key" not in hb["update"]["error"]:
            fail(f"rogue offer failed for another reason: {hb['update']['error']}")
        if (mock.out / "downloads.jsonl").exists():
            fail("the agent downloaded a package it could not verify")
        print(f"ok: package signed by an untrusted key refused: {hb['update']['error']}")

        # 2. the upgrade, through the running service
        seen = len(mock.heartbeats())
        mock.offer(new, 2)
        mock.wait(lambda h: h.get("version") == version_of(new) and (h.get("update") or {}).get("state") == "updated",
                  seen, 300, f"the upgrade to {version_of(new)}")
        stops = [h for h in mock.heartbeats()[seen:] if h.get("status") == "stopping"]
        if not any(h.get("reason") == "agent_update" for h in stops):
            fail(f"no stop reported as agent_update during the upgrade: {stops}")
        if installed_version() != version_of(new):
            fail(f"dpkg says {installed_version()}")
        if "token:" not in CONFIG.read_text() or "heartbeat_interval: 5" not in CONFIG.read_text():
            fail("the upgrade replaced the agent's config.yaml")
        print(f"ok: upgraded {version_of(old)} -> {version_of(new)} through systemd (config kept, stop reported as agent_update)")

        # 3. rollback: the rollout targets the older version again
        seen = len(mock.heartbeats())
        mock.offer(old, 3)
        mock.wait(lambda h: h.get("version") == version_of(old) and (h.get("update") or {}).get("state") == "updated",
                  seen, 300, f"the rollback to {version_of(old)}")
        if installed_version() != version_of(old):
            fail(f"dpkg says {installed_version()} after the rollback")
        print(f"ok: rolled back {version_of(new)} -> {version_of(old)} (dpkg downgrade)")
        print("UPDATE TEST PASSED")
    finally:
        mock.proc.kill()
        run("dpkg", "--purge", "siem-agent", check=False,
            env={"SIEM_UNINSTALL_TOKEN": "SMOKE-UNINS-TALLT-OKEN1"})


if __name__ == "__main__":
    main()
