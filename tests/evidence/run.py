#!/usr/bin/env python3
# tests/evidence/run.py
"""End-to-end fault harness for durable agent evidence.

    python tests/evidence/run.py --scenario <name> --count 10000 --output <dir>

Starts a uniquely named, disposable Compose project (tests/evidence/compose.yml:
PostgreSQL, Redis, Elasticsearch, server-api, worker, a fault proxy, the Linux
agent in durable mode and a log producer) on random loopback ports, injects
the scenario's fault while the producer writes `count` uniquely marked lines,
waits for the pipeline to settle and checks, by full set equality, that every
source line has exactly one inbox receipt and one Elasticsearch document (or,
where the scenario destroys evidence on purpose, that the loss is reported).
Artifacts (timeline, health, inbox and document extracts, service logs) go to
--output. Only that project's containers, networks and volumes are removed.

Scenarios: offline-restart, lost-response, redis-loss, worker-crash, quota,
corruption, retention."""
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from assertions import assert_delivery  # noqa: E402

COMPOSE = HERE / "compose.yml"
SOURCE = "/data/source.log"
BACKEND = ["postgres", "redis", "elasticsearch", "api", "api2", "worker", "proxy"]
LOG_TAIL = 5000  # lines kept per service log


def agent_config(evidence_extra: str = "") -> str:
    return f"""agent:
  name: evd-agent
  group: default
  enrollment_token: evidence-harness-enroll
  state_dir: /var/lib/siem-agent
server:
  url: http://proxy:8080
  heartbeat_interval: 5
logs:
  - path: {SOURCE}
    type: syslog
fim:
  enabled: false
firewall:
  enabled: false
  dry_run: true
netwatch:
  enabled: false
detect:
  enabled: false
buffer:
  spill_path: /var/lib/siem-agent/spill.log
evidence:
  enabled: true
{evidence_extra}"""


class Harness:
    def __init__(self, scenario: str, count: int, rate: float, output: Path, keep: bool):
        self.scenario, self.count, self.rate, self.keep = scenario, count, rate, keep
        self.run_id = secrets.token_hex(4)
        self.project = f"adsiem-evd-{scenario}-{self.run_id}"
        self.out = output
        self.out.mkdir(parents=True, exist_ok=True)
        self.env = {**os.environ, "EVD_RUN": self.run_id, "EVD_COUNT": str(count), "EVD_RATE": str(rate),
                    "EVD_AGENT_CONFIG": agent_config()}
        self.timeline: list[dict] = []
        self.facts: dict = {"scenario": scenario, "project": self.project, "count": count, "rate": rate}
        self.marker = re.compile(rf"evd-{self.run_id}-(\d{{7}})")
        self.agent_id: str | None = None
        self._ports: dict[tuple[str, int], int] = {}

    # -- plumbing ---------------------------------------------------------
    def mark(self, event: str, **fields) -> None:
        entry = {"t": round(time.time(), 3), "event": event, **fields}
        self.timeline.append(entry)
        print(f"[{self.project}] {event} {json.dumps(fields) if fields else ''}", flush=True)

    def compose(self, *args: str, check: bool = True, capture: bool = False, env: dict | None = None,
                timeout: float = 900) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-p", self.project, "-f", str(COMPOSE), *args]
        return subprocess.run(cmd, check=check, text=True, timeout=timeout, env={**self.env, **(env or {})},
                              stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.PIPE if capture else None)

    def port(self, service: str, container_port: int) -> int:
        key = (service, container_port)
        if key not in self._ports:
            out = self.compose("port", service, str(container_port), capture=True).stdout.strip()
            self._ports[key] = int(out.rsplit(":", 1)[1])
        return self._ports[key]

    def http(self, service: str, container_port: int, path: str, body: dict | None = None):
        url = f"http://127.0.0.1:{self.port(service, container_port)}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"null")

    def sql(self, query: str) -> list[str]:
        out = self.compose("exec", "-T", "postgres", "psql", "-U", "evd", "-d", "evd", "-At", "-v",
                           "ON_ERROR_STOP=1", "-c", query, capture=True).stdout
        return [line for line in out.splitlines() if line]

    def proxy(self, mode: str, rate: float = 0.0) -> dict:
        state = self.http("proxy", 8081, "/", {"mode": mode, "rate": rate})
        self.mark("proxy_mode", mode=mode, rate=rate)
        return state

    def written(self) -> int:
        return int(self.http("proxy", 8081, "/progress").get("written", 0))

    def wait_written(self, n: int, timeout: float = 600) -> None:
        deadline = time.time() + timeout
        while self.written() < n:
            if time.time() > deadline:
                raise TimeoutError(f"producer did not reach {n} lines")
            time.sleep(0.2)
        self.mark("written", lines=self.written())

    def kill(self, service: str) -> None:
        self.compose("kill", "-s", "SIGKILL", service)
        self.mark("sigkill", service=service)

    def start(self, service: str) -> None:
        self.compose("start", service)
        self.mark("start", service=service)

    # -- the system under test -------------------------------------------
    def up_backend(self) -> None:
        self.mark("backend_starting")
        self.compose("up", "-d", "--wait", *BACKEND)
        self.mark("backend_ready")

    def up_agent(self) -> None:
        self.compose("up", "-d", "--no-deps", "agent")
        self.mark("agent_started")
        deadline = time.time() + 180
        while time.time() < deadline:
            rows = self.sql("select id, approved, evidence_health is not null from agents where hostname = 'evd-agent'")
            if rows and rows[0].endswith("|t|t"):
                self.agent_id = rows[0].split("|")[0]
                self.mark("agent_reporting", agent_id=self.agent_id)
                return
            time.sleep(1)
        raise TimeoutError("the agent never enrolled and reported durable evidence health")

    def produce(self, count: int | None = None, start: int = 0) -> None:
        env = {"EVD_COUNT": str(count or self.count), "EVD_START": str(start)}
        self.compose("run", "-d", "--rm", "--no-deps", "-e", f"EVD_COUNT={env['EVD_COUNT']}",
                     "-e", f"EVD_START={start}", "producer", capture=True)
        self.mark("producer_started", **env)

    def health(self) -> dict | None:
        rows = self.sql(f"select evidence_health from agents where id = '{self.agent_id}'")
        return json.loads(rows[0]) if rows and rows[0] else None

    def inbox(self) -> list[dict]:
        rows = self.sql(f"""select json_build_object('receipt_id', receipt_id, 'event_id', event_id,
            'status', status, 'payload_bytes', payload_bytes, 'collected_at', collected_at,
            'raw_message', (payload #>> '{{}}')::jsonb ->> 'raw_message')
            from evidence_inbox where agent_id = '{self.agent_id}'""")
        return [json.loads(r) for r in rows]

    def documents(self) -> list[dict]:
        es = self.port("elasticsearch", 9200)
        base = f"http://127.0.0.1:{es}"

        def call(path, body=None, method="POST"):
            data = json.dumps(body).encode() if body is not None else None  # _refresh takes no body
            req = urllib.request.Request(base + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 404:  # nothing indexed yet
                    return {"hits": {"hits": []}}
                raise RuntimeError(f"elasticsearch {path}: {exc.code} {exc.read()[:500]!r}") from exc

        call("/logs/_refresh")
        query = {"size": 5000, "_source": ["raw_message", "agent_id"], "sort": ["_doc"],
                 "query": {"term": {"agent_id": self.agent_id}}}
        page = call("/logs/_search?scroll=1m", query)
        docs = []
        while page["hits"]["hits"]:
            docs += [{"_id": h["_id"], **h["_source"]} for h in page["hits"]["hits"]]
            page = call("/_search/scroll", {"scroll": "1m", "scroll_id": page["_scroll_id"]})
        if page.get("_scroll_id"):
            call("/_search/scroll", {"scroll_id": page["_scroll_id"]}, method="DELETE")
        return docs

    def ours(self, rows: list[dict]) -> list[dict]:
        """Rows that carry one of this run's markers, with the marker attached."""
        kept = []
        for r in rows:
            m = self.marker.search(r.get("raw_message") or "")
            if m:
                kept.append({**r, "marker": m.group(0)})
        return kept

    def settle(self, expected: int | None, timeout: float = 900, quiet: float = 45) -> tuple[list, list]:
        """Wait until every expected marker is indexed and nothing is pending,
        or (expected=None) until documents and the inbox stop changing."""
        deadline, last, since = time.time() + timeout, None, time.time()
        while True:
            docs = self.ours(self.documents())
            inbox = self.inbox()
            pending = sum(r["status"] == "pending" for r in inbox)
            state = (len(docs), len(inbox), pending)
            if state != last:
                last, since = state, time.time()
                self.mark("progress", documents=state[0], receipts=state[1], pending=pending)
            if expected is not None and len({d["marker"] for d in docs}) >= expected and pending == 0:
                break
            if expected is None and pending == 0 and time.time() - since >= quiet:
                break
            if time.time() > deadline:
                self.mark("settle_timeout", documents=state[0], receipts=state[1], pending=pending)
                break
            time.sleep(3)
        return docs, self.ours(inbox)

    def next_health(self, timeout: float = 150) -> dict | None:
        """The next health report (the agent refreshes it once a minute)."""
        query = f"select evidence_health_at from agents where id = '{self.agent_id}'"
        before = self.sql(query)
        deadline = time.time() + timeout
        while time.time() < deadline and self.sql(query) == before:
            time.sleep(3)
        return self.health()

    # -- checks -----------------------------------------------------------
    def check_delivery(self, expected: set[str], docs: list[dict], inbox: list[dict]) -> None:
        receipts = [{"event_id": r["marker"], "receipt_id": r["receipt_id"], "status": "accepted"} for r in inbox]
        documents = [{"event_id": d["marker"]} for d in docs]
        assert_delivery(expected, receipts, documents)
        self.check_identity(docs, inbox)

    def check_identity(self, docs: list[dict], inbox: list[dict]) -> None:
        """The document id is uuid5(agent, event id) of the line's one receipt."""
        event_of = {r["marker"]: r["event_id"] for r in inbox}
        agent = uuid.UUID(self.agent_id)
        wrong = [d["marker"] for d in docs
                 if d["marker"] in event_of and d["_id"] != str(uuid.uuid5(agent, event_of[d["marker"]]))]
        if wrong:
            raise AssertionError(f"{len(wrong)} documents with an unstable id (e.g. {wrong[:5]})")

    def markers(self, start: int, count: int) -> set[str]:
        return {f"evd-{self.run_id}-{n:07d}" for n in range(start, start + count)}

    # -- artifacts --------------------------------------------------------
    def save(self, name: str, data) -> None:
        path = self.out / name
        if isinstance(data, list):
            path.write_text("".join(json.dumps(x, default=str) + "\n" for x in data))
        else:
            path.write_text(json.dumps(data, indent=2, default=str))

    def collect_logs(self) -> None:
        logs = self.out / "logs"
        logs.mkdir(exist_ok=True)
        for service in [*BACKEND, "agent"]:
            out = self.compose("logs", "--no-color", "--tail", str(LOG_TAIL), service, check=False, capture=True)
            text = re.sub(r"(token|password|secret)([\"']?\s*[:=]\s*)\S+", r"\1\2<redacted>",
                          out.stdout + out.stderr, flags=re.I)
            (logs / f"{service}.log").write_text(text)

    def down(self) -> None:
        if self.keep:
            self.mark("kept", project=self.project)
            return
        self.compose("down", "-v", "--remove-orphans", "--timeout", "5", check=False, capture=True)
        self.mark("removed", project=self.project)


# -- scenarios -------------------------------------------------------------
def offline_restart(h: Harness) -> None:
    """Server unreachable while the agent is SIGKILLed and restarted."""
    h.produce()
    h.wait_written(h.count // 5)
    h.proxy("down")
    h.wait_written(h.count // 2)
    h.kill("agent")
    time.sleep(3)
    h.start("agent")
    h.wait_written(h.count * 4 // 5)
    h.proxy("pass")
    h.wait_written(h.count)
    docs, inbox = h.settle(h.count)
    h.check_delivery(h.markers(0, h.count), docs, inbox)


def lost_response(h: Harness) -> None:
    """A third of evidence responses are lost after the server committed."""
    h.proxy("drop_response", 0.3)
    h.produce()
    h.wait_written(h.count)
    time.sleep(10)
    h.facts["proxy"] = h.proxy("pass")
    if h.facts["proxy"]["dropped_responses"] == 0:
        raise AssertionError("no response was dropped: the scenario did not exercise retries")
    docs, inbox = h.settle(h.count)
    h.check_delivery(h.markers(0, h.count), docs, inbox)


def redis_loss(h: Harness) -> None:
    """Redis is SIGKILLed and comes back empty (streams and consumer groups gone)."""
    h.produce()
    h.wait_written(h.count * 3 // 10)
    h.kill("redis")
    time.sleep(5)
    h.start("redis")
    h.wait_written(h.count)
    docs, inbox = h.settle(h.count, timeout=900)
    h.check_delivery(h.markers(0, h.count), docs, inbox)


def worker_crash(h: Harness) -> None:
    """The worker is SIGKILLed twice mid-stream."""
    h.produce()
    for fraction in (0.25, 0.6):
        h.wait_written(int(h.count * fraction))
        h.kill("worker")
        time.sleep(5)
        h.start("worker")
    h.wait_written(h.count)
    docs, inbox = h.settle(h.count)
    h.check_delivery(h.markers(0, h.count), docs, inbox)


QUOTA_BYTES = 400_000


def quota(h: Harness) -> None:
    """The group budget is full: the agent backs off and keeps everything
    queued until capacity returns; the server never exceeds the budget."""
    h.produce()
    h.wait_written(h.count)
    time.sleep(20)
    used = int((h.sql("select coalesce(sum(payload_bytes), 0) from evidence_group_usage") or ["0"])[0])
    receipts = len(h.inbox())
    h.facts["quota"] = {"budget": QUOTA_BYTES, "used": used, "receipts_while_full": receipts}
    h.mark("quota_full", used=used, receipts=receipts)
    if used > QUOTA_BYTES:
        raise AssertionError(f"group usage {used} exceeds the budget {QUOTA_BYTES}")
    if receipts >= h.count:
        raise AssertionError("everything was accepted: the budget was never reached")
    health = h.next_health()
    h.facts["health_while_full"] = health
    sender = (health or {}).get("sender") or {}
    if sender.get("reason") != "status_429" or (health or {}).get("queued_events", 0) == 0:
        raise AssertionError(f"the agent does not report the full budget: {sender}")
    h.compose("up", "-d", "--no-deps", "api", "api2", env={"EVD_BUDGET_BYTES": str(1 << 30)})  # capacity returns
    h.mark("budget_raised")
    docs, inbox = h.settle(h.count)
    h.check_delivery(h.markers(0, h.count), docs, inbox)


def corruption(h: Harness) -> None:
    """Undelivered journal records are damaged while the agent is down. The
    agent refuses the journal and keeps it unchanged; -evidence-salvage then
    restores collection: everything readable is delivered, lines written while
    blocked and afterwards are not skipped, and what was destroyed is reported
    as a gap. Nothing may be duplicated or invented."""
    extra = max(h.count // 10, 10)
    h.proxy("down")
    h.produce()                      # batch A: in the journal when it is damaged
    h.wait_written(h.count)
    time.sleep(10)  # let the tailer admit everything
    h.kill("agent")
    # Damage the middle of the largest segment: an interior record, not a torn tail.
    script = ("set -e; f=$(ls -S /var/lib/siem-agent/evidence/segment-*.evj | head -1); "
              "s=$(stat -c %s \"$f\"); printf 'CORRUPTCORRUPTCORRUPT' | "
              "dd of=\"$f\" bs=1 seek=$((s / 2)) conv=notrunc 2>/dev/null; sha256sum \"$f\"; echo \"$s\"")

    def in_state_volume(command: str) -> str:
        return h.compose("run", "--rm", "--no-deps", "--entrypoint", "/bin/sh", "agent", "-c", command,
                         capture=True).stdout.strip()

    damaged = in_state_volume(script)
    h.mark("corrupted", segment=damaged)
    path, size = damaged.split()[1], damaged.split()[2]
    digest = damaged.split()[0]

    # 1. The agent refuses the damaged journal and changes nothing.
    h.start("agent")
    h.proxy("pass")
    blocked = h.next_health()
    h.facts["health_while_blocked"] = blocked
    if (blocked or {}).get("reason") != "journal_unavailable":
        raise AssertionError(f"a damaged journal was not reported: {blocked}")
    h.produce(extra, start=h.count)  # batch B: written while collection is blocked
    h.wait_written(extra)
    time.sleep(5)
    if h.ours(h.documents()):
        raise AssertionError("evidence was delivered from a journal that does not open")
    h.compose("stop", "agent")
    after = in_state_volume(f"sha256sum '{path}'; stat -c %s '{path}'")
    if after.split() != [digest, path, size]:
        raise AssertionError(f"the damaged segment changed while blocked: {damaged!r} -> {after!r}")

    # 2. Salvage, then the agent runs again.
    out = h.compose("run", "--rm", "--no-deps", "--entrypoint", "/usr/local/bin/siem-agent", "agent",
                    "-config", "/etc/siem-agent/config.yaml", "-evidence-salvage",
                    "-reason", "acceptance: corruption scenario", capture=True).stdout
    h.mark("salvaged", output=out.strip().splitlines()[0] if out.strip() else "")
    h.facts["salvage_output"] = out
    name = path.rsplit("/", 1)[1]
    kept = in_state_volume(f"sha256sum /var/lib/siem-agent/evidence.corrupt-*/{name}").split()
    if not kept or kept[0] != digest:
        raise AssertionError(f"the damaged journal was not kept unchanged by salvage: {kept}")
    h.start("agent")
    h.produce(extra, start=h.count + extra)  # batch C: after salvage
    h.wait_written(extra)
    docs, inbox = h.settle(None)
    health = h.next_health()

    produced = h.markers(0, h.count + 2 * extra)
    got_docs = [d["marker"] for d in docs]
    got_receipts = [r["marker"] for r in inbox]
    for what, got in (("documents", got_docs), ("receipts", got_receipts)):
        if len(got) != len(set(got)):
            raise AssertionError(f"duplicate {what} after salvage")
        if set(got) - produced:
            raise AssertionError(f"{what} for lines that were never written")
    h.check_identity(docs, inbox)
    missing = produced - set(got_docs)
    later = h.markers(h.count, 2 * extra)
    h.facts.update(missing_after_salvage=len(missing), health_after_salvage=health)
    if missing & later:
        raise AssertionError(f"{len(missing & later)} lines written while blocked or after salvage were skipped")
    if len(missing) > 5:  # 21 damaged bytes destroy at most a couple of records
        raise AssertionError(f"{len(missing)} lines lost: salvage kept less than the readable evidence")
    if (health or {}).get("reason") == "journal_unavailable":
        raise AssertionError(f"still blocked after salvage: {health}")
    if missing and not (health or {}).get("unknown_gaps"):
        raise AssertionError(f"{len(missing)} lines destroyed but no gap reported: {health}")


def retention(h: Harness) -> None:
    """Completed payloads are released after 7 days (and their budget), receipts
    after 30; pending evidence never ages out and is still delivered."""
    h.produce()
    h.wait_written(h.count)
    docs, inbox = h.settle(h.count)
    h.check_delivery(h.markers(0, h.count), docs, inbox)
    h.compose("stop", "worker")
    h.mark("worker_stopped")
    extra = max(h.count // 10, 10)
    h.produce(extra, start=h.count)
    deadline = time.time() + 300
    while sum(r["status"] == "pending" for r in h.inbox()) < extra:
        if time.time() > deadline:
            raise TimeoutError("the second batch was not received")
        time.sleep(2)

    def retain(days: int) -> int:
        code = ("import asyncio, datetime as d; from worker.evidence_inbox import evidence_retention_once as r\n"
                f"now = d.datetime.now(d.timezone.utc) + d.timedelta(days={days})\n"
                "async def main():\n  n = 0\n  while (k := await r(now)) > 0: n += k\n  print(n)\n"
                "asyncio.run(main())")
        out = h.compose("run", "--rm", "--no-deps", "worker", "python", "-c", code, capture=True).stdout
        n = int(out.strip().splitlines()[-1])
        h.mark("retention", days=days, affected=n)
        return n

    retain(8)
    rows = h.inbox()
    pending = [r for r in rows if r["status"] == "pending"]
    completed = [r for r in rows if r["status"] == "completed"]
    used = int(h.sql("select coalesce(sum(payload_bytes), 0) from evidence_group_usage")[0])
    h.facts["after_8_days"] = {"completed": len(completed), "pending": len(pending), "used": used}
    if any(r["raw_message"] is not None for r in completed):
        raise AssertionError("completed payloads were kept past 7 days")
    if any(r["raw_message"] is None for r in pending) or len(pending) != extra:
        raise AssertionError("pending evidence lost its payload to retention")
    if used != sum(r["payload_bytes"] for r in pending):
        raise AssertionError(f"group budget not released: used {used}")
    retain(31)
    statuses = [r["status"] for r in h.inbox()]
    h.facts["after_31_days"] = {"rows": len(statuses), "pending": statuses.count("pending")}
    if statuses.count("completed") or statuses.count("pending") != extra:
        raise AssertionError(f"after 31 days: {h.facts['after_31_days']}")
    h.start("worker")
    docs, inbox = h.settle(h.count + extra)
    expected = h.markers(0, h.count + extra)
    if {d["marker"] for d in docs} != expected or len(docs) != len(expected):
        raise AssertionError("documents changed by retention, or pending evidence was not delivered")
    h.check_identity(docs, inbox)


SCENARIOS = {
    "offline-restart": offline_restart,
    "lost-response": lost_response,
    "redis-loss": redis_loss,
    "worker-crash": worker_crash,
    "quota": quota,
    "corruption": corruption,
    "retention": retention,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--rate", type=float, default=500, help="producer lines per second")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build", action="store_true", help="build the api, worker and agent images first")
    parser.add_argument("--keep", action="store_true", help="leave the project running for inspection")
    args = parser.parse_args()

    h = Harness(args.scenario, args.count, args.rate, args.output, args.keep)
    if args.scenario == "quota":
        h.env["EVD_BUDGET_BYTES"] = str(QUOTA_BYTES)
    ok, error = False, None
    try:
        if args.build:
            h.compose("build", "api", "worker", "agent")
        h.up_backend()
        h.up_agent()
        SCENARIOS[args.scenario](h)
        h.facts["final_health"] = h.health()
        ok = True
    except Exception as exc:  # noqa: BLE001 - every failure is reported in result.json
        error = f"{type(exc).__name__}: {exc}"
        h.mark("failed", error=error)
    finally:
        try:
            if h.agent_id:
                h.save("inbox.jsonl", [{k: v for k, v in r.items() if k != "raw_message"} | {"marker": r["marker"]}
                                       for r in h.ours(h.inbox())])
                h.save("documents.jsonl", [{"_id": d["_id"], "marker": d["marker"]} for d in h.ours(h.documents())])
            h.collect_logs()
        except Exception as exc:  # noqa: BLE001
            h.mark("artifact_collection_failed", error=str(exc))
        h.save("timeline.jsonl", h.timeline)
        h.save("result.json", {**h.facts, "passed": ok, "error": error})
        h.down()
    print(json.dumps({"scenario": args.scenario, "passed": ok, "error": error, "output": str(args.output)}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
