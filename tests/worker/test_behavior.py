# tests/worker/test_behavior.py
"""Host behaviour baselines (worker/worker/behavior.py): rare parent → child,
new rare executable and beaconing from Linux and Windows telemetry, and the
siem_behavior decoder and rules they feed."""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../worker"))

import pytest  # noqa: E402
import yaml  # noqa: E402

from worker import behavior  # noqa: E402
from worker.decoder_engine import DecoderEngine  # noqa: E402
from worker.sigma_engine import SigmaEngine  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "../..")
HOUR = 3600


class FakeRedis:
    def __init__(self):
        self.kv, self.sets, self.lists, self.stream = {}, {}, {}, []

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def get(self, key):
        return self.kv.get(key)

    async def expire(self, key, seconds):
        return True

    async def sadd(self, key, member):
        self.sets.setdefault(key, set()).add(member)

    async def scard(self, key):
        return len(self.sets.get(key, ()))

    async def sismember(self, key, member):
        return member in self.sets.get(key, ())

    async def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    async def ltrim(self, key, start, end):
        self.lists[key] = self.lists.get(key, [])[start:end + 1]

    async def lrange(self, key, start, end):
        items = self.lists.get(key, [])
        return items[start:] if end == -1 else items[start:end + 1]

    async def xadd(self, stream, data):
        self.stream.append(data)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture(autouse=True)
def default_settings(monkeypatch):
    async def get_setting(key, default=""):
        return default
    monkeypatch.setattr(behavior, "get_setting", get_setting)


def run(coro):
    return asyncio.run(coro)


def proc(parent, image, cmd=""):
    return {"Image": image, "ParentImage": parent, "CommandLine": cmd}


def test_rare_parent_child_after_learning_only():
    r, clock = FakeRedis(), Clock()
    b = behavior.Behavior(r, now=clock)
    # learning: a never-seen pair is only remembered
    assert run(b.process("h1", "blue", proc("/usr/sbin/nginx", "/usr/sbin/nginx"))) == []
    assert run(b.process("h1", "blue", proc("C:\\Windows\\explorer.exe", "C:\\Program Files\\x\\a.exe"))) == []
    clock.t += 73 * HOUR
    found = run(b.process("h1", "blue", proc("/usr/sbin/nginx", "/bin/sh", "sh -c id")))
    assert found == [("behavior_rare_parent_child", {"parent": "/usr/sbin/nginx", "image": "/bin/sh",
                                                     "pair": "nginx>sh", "fleet_hosts": 1,
                                                     "command_line": "sh -c id"})]
    assert run(b.process("h1", "blue", proc("/usr/sbin/nginx", "/bin/sh"))) == []  # seen now
    # a pair many hosts run is normal, even when new to this host
    for h in ("h2", "h3"):
        run(b.process(h, "blue", proc("/usr/lib/systemd/systemd", "/usr/bin/cron")))
    assert run(b.process("h1", "blue", proc("/usr/lib/systemd/systemd", "/usr/bin/cron"))) == []
    # Windows paths compare by file name, case-insensitively
    found = run(b.process("h1", "blue", proc("C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                                              "C:\\Windows\\System32\\cmd.exe")))
    assert found[0][1]["pair"] == "winword.exe>cmd.exe"


def test_new_rare_executable_only_from_user_writable_folders():
    r, clock = FakeRedis(), Clock()
    b = behavior.Behavior(r, now=clock)
    run(b.process("h1", "blue", proc("/bin/bash", "/usr/bin/ls")))  # starts the learning clock
    clock.t += 73 * HOUR
    found = run(b.process("h1", "blue", proc("/bin/bash", "/tmp/.x/kworkerd")))
    assert ("behavior_new_rare_executable",
            {"image": "/tmp/.x/kworkerd", "parent": "/bin/bash", "fleet_hosts": 1}) in found
    win = run(b.process("h1", "blue", proc("C:\\Windows\\explorer.exe",
                                            "C:\\Users\\a\\Downloads\\invoice.exe")))
    assert any(e == "behavior_new_rare_executable" for e, _ in win)
    assert not any(e == "behavior_new_rare_executable"
                   for e, _ in run(b.process("h1", "blue", proc("/bin/bash", "/usr/local/bin/tool"))))
    # a program another host already runs from the same place is not rare
    run(b.process("h2", "blue", proc("/bin/bash", "/home/dev/bin/build.sh")))
    assert not any(e == "behavior_new_rare_executable"
                   for e, _ in run(b.process("h1", "blue", proc("/bin/bash", "/home/dev/bin/build.sh"))))


def connect(dst, port="443", comm="update"):
    return {"destination.address": dst, "destination.port": port, "process.name": comm}


def beacon(b, host, dst, gaps, start=1_800_000_000.0, log_type="linux_network_connect", port="443", comm="implant"):
    t, found = start, []
    for g in [0] + gaps:
        t += g
        found += run(b.network(host, "blue", log_type, connect(dst, port, comm), t))
    return found


def test_beaconing_steady_rhythm_reported_once():
    b = behavior.Behavior(FakeRedis())
    gaps = [60, 61, 59, 60, 62, 58, 60, 61, 60]
    found = beacon(b, "h1", "45.33.32.156", gaps)
    assert len(found) == 1
    event, fields = found[0]
    assert event == "behavior_beaconing" and fields["destination"] == "45.33.32.156" and fields["port"] == 443
    assert 59 <= fields["interval_s"] <= 61 and fields["jitter"] <= 0.05 and fields["image"] == "implant"
    assert beacon(b, "h1", "45.33.32.156", [60] * 5, start=1_800_001_000.0) == []  # once a day


@pytest.mark.parametrize("dst,port,gaps", [
    ("45.33.32.156", "443", [5, 300, 12, 900, 40, 61, 2000, 33, 80]),  # irregular: a person browsing
    ("45.33.32.156", "443", [2, 2, 2, 2, 2, 2, 2, 2, 2]),              # faster than 10 s: a burst
    ("10.0.0.5", "443", [60] * 9),                                     # internal destination
    ("8.8.8.8", "53", [60] * 9),                                       # DNS is periodic by design
])
def test_not_beaconing(dst, port, gaps):
    assert beacon(behavior.Behavior(FakeRedis()), "h1", dst, gaps, port=port) == []


def test_a_destination_many_hosts_call_on_a_timer_is_a_fleet_service():
    b = behavior.Behavior(FakeRedis())
    results = [beacon(b, f"h{i}", "52.84.1.1", [300] * 9, comm="updater") for i in range(5)]
    assert [len(r) for r in results] == [1, 1, 1, 0, 0]


def test_windows_and_snapshot_telemetry():
    b = behavior.Behavior(FakeRedis())
    t, found = 1_800_000_000.0, []
    for _ in range(10):
        t += 120
        found += run(b.network("w1", "blue", "windows_etw_network",
                               {"destination.ip": "45.33.32.156", "destination.port": "8443",
                                "Image": "C:\\Users\\a\\AppData\\Roaming\\svc.exe", "Initiated": "true"}, t))
    assert len(found) == 1 and found[0][1]["image"].endswith("svc.exe")
    inbound = {"destination.ip": "45.33.32.156", "destination.port": "3389", "Image": "svchost.exe", "Initiated": "false"}
    assert run(b.network("w1", "blue", "windows_etw_network", inbound, t)) == []
    raw = 'tcp ESTAB 0 0 10.0.0.5:51000 [2606:4700:4700::1111]:443 users:(("beacon",pid=777,fd=3))'
    assert behavior._ss_peer(raw) == ("2606:4700:4700::1111", "443", "beacon")
    found = []
    for i in range(10):
        found += run(b.network("l1", "blue", "linux_network_snapshot", {}, 1_800_000_000.0 + 600 * i, raw))
    assert found and found[0][1]["destination"] == "2606:4700:4700::1111"


def test_the_agents_own_connections_are_ignored():
    b = behavior.Behavior(FakeRedis())
    assert beacon(b, "h1", "45.33.32.156", [5] * 3 + [30] * 9, comm="siem-agent") == []
    assert behavior.outbound_connection("windows_etw_network", {
        "Initiated": "true", "destination.ip": "45.33.32.156", "destination.port": "443",
        "Image": "C:\\Program Files\\SIEMAgent\\siem-agent.exe"}) is None


def test_event_time_is_preferred_over_arrival():
    b = behavior.Behavior(FakeRedis())
    found = []
    for i in range(10):  # all arrive at once (a spilled batch) but happened a minute apart
        ev = {**connect("45.33.32.156"), "event.start": f"2026-11-13T08:{i:02d}:00.000000Z"}
        found += run(b.network("h1", "blue", "linux_network_connect", ev, 1_800_000_000.0))
    assert len(found) == 1 and found[0][1]["interval_s"] == 60.0


def test_observe_pushes_stream_lines_and_ignores_other_types():
    r = FakeRedis()
    events = run(behavior.observe(r, log_type="syslog", decoded={}, agent_id="a", group_id="blue",
                                  hostname="h", received=0.0))
    assert events == [] and r.stream == []
    t = 1_800_000_000.0
    for i in range(10):
        run(behavior.observe(r, log_type="linux_network_connect", decoded=connect("45.33.32.156"),
                             agent_id="a", group_id="blue", hostname="web-01", received=t + 60 * i))
    assert len(r.stream) == 1
    entry = r.stream[0]
    assert entry["log_type"] == "siem_behavior" and entry["hostname"] == "web-01"
    assert entry["raw_message"].startswith("event=behavior_beaconing image=update destination=45.33.32.156 port=443")


@pytest.fixture(scope="module")
def engines():
    load = lambda p: [open(f).read() for f in sorted(glob.glob(os.path.join(ROOT, p)))]  # noqa: E731
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    sig = SigmaEngine()
    sig.load_from_yaml_list(load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return dec, sig


@pytest.mark.parametrize("event,fields,title", [
    ("behavior_rare_parent_child", {"parent": "/usr/sbin/nginx", "image": "/bin/sh", "pair": "nginx>sh",
                                    "fleet_hosts": 1, "command_line": "sh -c id"},
     "Rare Parent-Child Process On Host"),
    ("behavior_new_rare_executable", {"image": "C:\\Users\\a\\Downloads\\invoice.exe",
                                      "parent": "C:\\Windows\\explorer.exe", "fleet_hosts": 1},
     "New Rare Executable From User-Writable Folder"),
    ("behavior_beaconing", {"image": "implant", "destination": "45.33.32.156", "port": 443, "interval_s": 60.0,
                            "jitter": 0.017, "connections": 10, "fleet_hosts": 1},
     "Periodic Beaconing To External Host"),
])
def test_findings_become_alerts(engines, event, fields, title):
    dec, sig = engines
    raw = behavior.line(event, **fields)
    decoded, name = dec.decode_named("siem_behavior", raw)
    assert name == "siem_behavior" and decoded["event.action"] == event
    fired = {m["title"] for m in asyncio.run(sig.evaluate(dict(decoded, raw_message=raw, log_type="siem_behavior")))}
    assert title in fired
