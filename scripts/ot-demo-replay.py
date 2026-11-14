#!/usr/bin/env python3
"""Replay an OT attack, as Suricata would log it, into ADSIEM.

The scenario: an attacker who got onto the engineering workstation of a fuel
depot attacks the Modbus PLC that runs its pumps and the DNP3 RTU of the
substation that feeds it, while an internet scanner probes the exposed PLC.
Each step is the eve.json record Suricata's Modbus/DNP3 parsers write, so it
exercises the real decoders (decoders/suricata_eve_{modbus,dnp3}.yaml) and
rules (rules/ot_*.yaml). Routine HMI polling is mixed in and stays quiet.

Send it to the syslog receiver; the sending host must be registered under
Syslog Sources with log type "suricata" (docs/operations/ot-ics-detection.md):

    python3 scripts/ot-demo-replay.py --host <siem-host> --port 514
    python3 scripts/ot-demo-replay.py --host <siem-host> --tcp --delay 2

or append to the eve.json an agent tails (log type "suricata"):

    python3 scripts/ot-demo-replay.py --print >> /var/log/suricata/eve.json

Standard library only; the addresses are documentation/private ranges.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from datetime import datetime, timezone

HMI = "10.20.0.50"           # the operators' HMI: polls and writes setpoints all day
EWS = "10.20.0.77"           # engineering workstation, compromised
PLC = "10.20.1.10"           # Modbus PLC running the depot's fuel pumps
RTU = "10.30.0.5"            # DNP3 RTU of the substation feeding the depot
SCANNER = "185.220.101.7"    # internet scanner
ATTACKER_C2 = "45.129.56.138"  # attacker controlling the PLC directly from the internet

_flow = 1000


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def _base(event_type: str, src: str, dst: str, dport: int, proto: str | None) -> dict:
    global _flow
    _flow += 1
    rec = {"timestamp": _now(), "flow_id": _flow, "in_iface": "eth1", "event_type": event_type,
           "src_ip": src, "src_port": 40000 + _flow % 20000, "dest_ip": dst, "dest_port": dport,
           "proto": "TCP", "host": "ot-sensor-1"}
    if proto:
        rec["app_proto"] = proto
    return rec


def modbus(src: str, fc: int, unit: int = 1, dst: str = PLC, **request) -> dict:
    rec = _base("modbus", src, dst, 502, "modbus")
    req = {"transaction_id": _flow % 65535, "protocol_id": 0, "unit_id": unit, "function_raw": fc,
           "function_code": f"Fc{fc}", "category": "PUBLIC_ASSIGNED"}
    req.update(request)
    rec["modbus"] = {"id": 1, "request": req}
    return rec


def dnp3(src: str, fc: int, dst: str = RTU) -> dict:
    rec = _base("dnp3", src, dst, 20000, "dnp3")
    rec["dnp3"] = {"type": "request", "id": 0, "src": 3, "dst": 10,
                   "control": {"dir": True, "pri": True, "fcb": False, "fcv": False, "function_code": 4},
                   "application": {"control": {"fir": True, "fin": True, "con": False, "uns": False,
                                               "sequence": _flow % 16},
                                   "function_code": fc, "objects": [], "complete": True}}
    return rec


def flow(src: str, dst: str, dport: int) -> dict:
    rec = _base("flow", src, dst, dport, None)
    rec["flow"] = {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 180, "bytes_toclient": 120,
                   "state": "established", "reason": "timeout"}
    return rec


def routine() -> list[dict]:
    """What the OT network does all day: no alert."""
    return [modbus(HMI, 3, read={"address": 40001, "quantity": 10}), modbus(HMI, 4, read={"address": 30001, "quantity": 4}),
            modbus(HMI, 6, write={"address": 40010, "data": 72}), dnp3(HMI, 1)]


# (what happens, records). The expected alert is in the comment.
SCENARIO: list[tuple[str, list[dict]]] = [
    ("routine HMI polling (quiet)", routine()),
    ("internet scanner reaches the PLC's Modbus port", [flow(SCANNER, PLC, 502)]),
    # → OT Service Reached From The Internet (high)
    ("attacker on the engineering workstation fingerprints the PLC",
     [modbus(EWS, 43, mei={"raw": 14, "code": "ReadDeviceId"}), modbus(EWS, 17)]),
    # → Modbus Device Identification Query (medium)
    ("...tries every function code to see what the PLC accepts",
     [modbus(EWS, fc) for fc in (1, 2, 3, 4, 5, 6, 15, 16)]),
    # → Modbus Function Code Scan (high)
    ("...and sweeps the unit IDs behind the gateway", [modbus(EWS, 3, unit=u) for u in range(1, 13)]),
    # → Modbus Unit ID Sweep (high)
    ("routine HMI polling (quiet)", routine()),
    ("UMAS programming command: stop the PLC and download new logic",
     [modbus(EWS, 90, umas={"raw": 0x41, "code": "StopPLC"})]),
    # → Modbus PLC Programming Command (UMAS) (critical)
    ("force the PLC into listen-only: the HMI loses view and control",
     [modbus(EWS, 8, diagnostic={"raw": 4, "code": "ForceListenOnlyMode"})]),
    # → Modbus Diagnostics Restart Or Listen-Only Command (high)
    ("blind the SCADA master: disable unsolicited reporting on the substation RTU", [dnp3(EWS, 21)]),
    # → DNP3 Unsolicited Reporting Disabled (high)
    ("cold-restart the RTU, then stop its application", [dnp3(EWS, 13), dnp3(EWS, 18)]),
    # → DNP3 Outstation Restart Or Stop Command (critical)
    ("wipe the RTU's configuration file", [dnp3(EWS, 27)]),
    # → DNP3 File Deleted On Outstation (high)
    ("the attacker also writes pump setpoints straight from the internet",
     [modbus(ATTACKER_C2, 6, write={"address": 40010, "data": 0}),
      modbus(ATTACKER_C2, 5, write={"address": 1, "data": 0})]),
    # → OT Control Command From The Internet (critical)
]


def syslog_line(record: dict) -> str:
    """RFC 3164, as rsyslog's imfile forwards eve.json: <PRI>Mmm dd hh:mm:ss host tag: msg."""
    now = datetime.now()
    return f"<14>{now:%b} {now.day:2d} {now:%H:%M:%S} ot-sensor-1 suricata: {json.dumps(record, separators=(',', ':'))}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", help="ADSIEM syslog receiver")
    ap.add_argument("--port", type=int, default=514)
    ap.add_argument("--tcp", action="store_true", help="TCP instead of UDP")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between steps (default 1)")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="write the eve.json lines to stdout instead of sending them")
    args = ap.parse_args()
    if not args.print_only and not args.host:
        ap.error("--host is required unless --print")

    sock = None
    if not args.print_only:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if args.tcp else socket.SOCK_DGRAM)
        if args.tcp:
            sock.connect((args.host, args.port))
    sent = 0
    for i, (what, records) in enumerate(SCENARIO, 1):
        print(f"[{i:2}/{len(SCENARIO)}] {what}", file=sys.stderr)
        for rec in records:
            rec["timestamp"] = _now()
            if args.print_only:
                print(json.dumps(rec, separators=(",", ":")))
                continue
            data = (syslog_line(rec) + ("\n" if args.tcp else "")).encode()
            if args.tcp:
                sock.sendall(data)
            else:
                sock.sendto(data, (args.host, args.port))
            sent += 1
        if not args.print_only and args.delay:
            time.sleep(args.delay)
    if sock is not None:
        sock.close()
        print(f"sent {sent} records to {args.host}:{args.port}/{'tcp' if args.tcp else 'udp'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
