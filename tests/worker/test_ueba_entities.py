# tests/worker/test_ueba_entities.py
"""UEBA host and process entities from agent telemetry, and per-group
population baselines (worker/worker/ueba)."""
import asyncio
import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402

from worker.ueba import explain as ex  # noqa: E402
from worker.ueba import features as ft  # noqa: E402
from worker.ueba import scorer, trainer  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.kv, self.sets, self.hashes = {}, {}, {}

    async def incr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        return self.kv[key]

    async def expire(self, key, seconds):
        return True

    async def get(self, key):
        v = self.kv.get(key)
        return None if v is None else str(v)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def sadd(self, key, member):
        self.sets.setdefault(key, set()).add(member)

    async def scard(self, key):
        return len(self.sets.get(key, ()))

    async def sismember(self, key, member):
        return member in self.sets.get(key, ())

    async def smembers(self, key):
        return set(self.sets.get(key, ()))

    async def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = value

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))


def run(coro):
    return asyncio.run(coro)


def started(image, parent="/bin/bash", host="web-01"):
    return {"Image": image, "ParentImage": parent, "hostname": host}


def test_host_and_process_counters_from_linux_process_starts():
    r = FakeRedis()
    run(scorer._telemetry_counters(r, started("/usr/bin/ls"), "blue", "linux_process_exec"))
    run(scorer._telemetry_counters(r, started("/usr/bin/ls"), "blue", "linux_process_exec"))
    run(scorer._telemetry_counters(r, started("/bin/sh", "/usr/sbin/nginx"), "blue", "linux_process_exec"))
    run(scorer._telemetry_counters(r, started("/tmp/.x/miner", "/bin/sh"), "blue", "linux_process_exec"))
    host = run(ft.build_host_vector_dict(r, "web-01"))
    assert host["process_count"] == 4 and host["unique_processes"] == 3
    # the first program a host is seen with is history, not "new"; later ones are new
    assert host["new_processes"] == 2
    assert host["shell_spawns"] == 1          # nginx → sh; sh → miner is not a shell start
    assert host["user_writable_execs"] == 1   # /tmp/.x/miner
    proc = run(ft.build_process_vector_dict(r, "sh@blue"))
    assert proc["exec_count"] == 1 and proc["unique_parents"] == 1 and proc["unique_hosts"] == 1
    assert r.hashes["ueba:group:host"]["web-01"] == "blue" and r.hashes["ueba:group:process"]["ls@blue"] == "blue"


def test_network_telemetry_counts_outbound_only():
    r = FakeRedis()
    win = {"hostname": "win-01", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           "Initiated": "true", "destination.ip": "45.33.32.156", "destination.port": "443"}
    touched = run(scorer._telemetry_counters(r, win, "blue", "windows_etw_network"))
    assert touched == [("host", "win-01"), ("process", "powershell.exe@blue")]
    run(scorer._telemetry_counters(r, {**win, "destination.ip": "10.0.0.7", "destination.port": "445"}, "blue",
                                   "windows_etw_network"))
    assert run(scorer._telemetry_counters(r, {**win, "Initiated": "false"}, "blue", "windows_etw_network")) == []
    linux = {"hostname": "web-01", "process.name": "curl", "destination.address": "127.0.0.1", "destination.port": "80"}
    assert run(scorer._telemetry_counters(r, linux, "blue", "linux_network_connect")) == []
    host = run(ft.build_host_vector_dict(r, "win-01"))
    # internal destinations count too: an internal sweep is exactly what this should see
    assert host["outbound_conns"] == 2 and host["unique_dest_ips"] == 2 and host["unique_dest_ports"] == 2
    assert run(ft.build_process_vector_dict(r, "powershell.exe@blue"))["unique_dest_ips"] == 2
    assert run(scorer._telemetry_counters(r, {"hostname": "h"}, "blue", "syslog")) == []


def _host_rows(n=48, **over):
    return [{**{k: 0.0 for k in ft.HOST_FEATURE_KEYS}, "process_count": 300.0, "unique_processes": 40.0,
             "new_processes": float(i % 2), "outbound_conns": 50.0, "unique_dest_ips": 6.0 + i % 3,
             "unique_dest_ports": 3.0, "hour_of_day": float(i % 24), **over} for i in range(n)]


def test_host_reasons_and_mitre():
    base = ex.build_baseline(_host_rows(), ft.HOST_FEATURE_KEYS)
    attack = {**_host_rows(1)[0], "new_processes": 9.0, "shell_spawns": 6.0, "unique_dest_ports": 180.0,
              "unique_dest_ips": 7.0}
    reasons = ex.explain("host", attack, None, base, "group blue")
    features = {r["feature"] for r in reasons}
    assert {"new_processes", "shell_spawns", "unique_dest_ports"} <= features
    assert all("group blue" in r["text"] for r in reasons if r["feature"] != "hour_of_day")
    mitre = {m["id"] for m in ex.mitre_for("host", reasons)}
    assert {"T1204", "T1059", "T1046"} <= mitre
    normal = _host_rows(1)[0]
    assert ex.explain("host", normal, None, base) == []


def test_process_spreading_to_many_hosts():
    rows = [{**{k: 0.0 for k in ft.PROCESS_FEATURE_KEYS}, "exec_count": 4.0, "unique_hosts": 1.0 + i % 2,
             "unique_parents": 1.0, "hour_of_day": float(i % 24)} for i in range(48)]
    base = ex.build_baseline(rows, ft.PROCESS_FEATURE_KEYS)
    psexec = {**rows[0], "exec_count": 14.0, "unique_hosts": 12.0}
    reasons = ex.explain("process", psexec, None, base)
    assert reasons[0]["feature"] == "unique_hosts"
    assert ex.mitre_for("process", reasons)[0]["id"] == "T1570"


def test_group_baseline_is_preferred_over_the_global_one():
    r = FakeRedis()
    bundle = SimpleNamespace(baseline={"_n": 999})
    assert run(scorer._population(r, "host", "blue", bundle)) == ({"_n": 999}, "all entities")
    r.kv["ueba:baseline:host:blue"] = json.dumps({"_n": 60, "shell_spawns": {"median": 0}})
    pop, scope = run(scorer._population(r, "host", "blue", bundle))
    assert pop["_n"] == 60 and scope == "group blue"
    assert run(scorer._population(r, "host", "red", bundle))[1] == "all entities"


def test_trainer_group_baselines_and_activity_filter():
    r = FakeRedis()
    rows = [SimpleNamespace(group_id="blue", features=f) for f in _host_rows(60)]
    rows += [SimpleNamespace(group_id="red", features=f) for f in _host_rows(10)]
    assert run(trainer._store_group_baselines(r, "host", rows, ft.HOST_FEATURE_KEYS)) == 1
    assert json.loads(r.kv["ueba:baseline:host:blue"])["_n"] == 60 and "ueba:baseline:host:red" not in r.kv
    idle = SimpleNamespace(features={"process_count": 0, "outbound_conns": 0})
    net_only = SimpleNamespace(features={"process_count": 0, "outbound_conns": 3})
    assert trainer.active_snapshots("host", [idle, net_only]) == [net_only]


def test_host_and_process_scoring_is_throttled(monkeypatch):
    r = FakeRedis()
    scored = []

    async def loaded(redis):
        return True

    async def handle(redis, entity_type, value, bundle, feat, group_id, decoded):
        scored.append((entity_type, value))

    monkeypatch.setattr(scorer, "_load_models", loaded)
    monkeypatch.setattr(scorer, "_handle_score", handle)
    monkeypatch.setitem(scorer._bundles, "host", object())
    monkeypatch.setitem(scorer._bundles, "process", object())
    for _ in range(5):
        run(scorer.score_event(r, started("/usr/bin/ls"), "blue", "linux_process_exec"))
    assert scored == [("host", "web-01"), ("process", "ls@blue")]


@pytest.mark.parametrize("raw,want", [
    ("alice", "alice"),
    ("root", "root"),
    ("28696E76616C6964207573657229", None),   # auditd hex of "(invalid user)"
    ("(invalid user)", None),
    ("(unknown)", None),
    ("?", None),
    ("-", None),
    ("", None),
    (None, None),
    ("64657669636520757365", "device use"),   # other auditd hex is decoded, not dropped
    ("deadbeef", "deadbeef"),                 # hex that is not printable text stays as written
])
def test_clean_user(raw, want):
    assert scorer.clean_user(raw) == want


def test_invalid_user_never_becomes_a_ueba_entity(monkeypatch):
    r = FakeRedis()

    async def cold(redis):
        return False
    monkeypatch.setattr(scorer, "_load_models", cold)
    run(scorer.score_event(r, {"user.name": "28696E76616C6964207573657229", "source.ip": "45.148.10.157",
                               "event.action": "login_failed", "hostname": "web-01"}, "blue", "linux_audit"))
    assert "ueba:active:users" not in r.sets
    assert r.sets["ueba:active:ips"] == {"45.148.10.157"}  # the source IP is still tracked
