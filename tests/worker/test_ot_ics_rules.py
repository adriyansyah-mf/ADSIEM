"""OT / ICS detection on Suricata EVE records: the Modbus and DNP3 decoders
and the ot_*.yaml rules, from the eve.json lines Suricata writes (sent over
syslog or by the agent, log type "suricata")."""
import asyncio
import glob
import json
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
_LOOP = asyncio.new_event_loop()  # not asyncio.run(): later modules need a current loop

HMI, PLC, OUTSIDER = "10.20.0.50", "10.20.1.10", "185.220.101.7"


def modbus(fc, src=HMI, unit=1, request=None, response=None, dst=PLC):
    req = {"transaction_id": 7, "protocol_id": 0, "unit_id": unit, "function_raw": fc,
           "function_code": f"Fc{fc}", "access_type": "WRITE SINGLE", "category": "PUBLIC_ASSIGNED"}
    req.update(request or {})
    rec = {"timestamp": "2026-11-15T01:02:03.000000+0700", "flow_id": 1234, "event_type": "modbus",
           "src_ip": src, "src_port": 50211, "dest_ip": dst, "dest_port": 502, "proto": "TCP",
           "app_proto": "modbus", "host": "ot-sensor-1", "modbus": {"id": 1, "request": req}}
    if response is not None:
        rec["modbus"]["response"] = response
    return json.dumps(rec)


def dnp3(fc, src=HMI, kind="request"):
    return json.dumps({"timestamp": "2026-11-15T01:02:03.000000+0700", "flow_id": 99, "event_type": "dnp3",
                       "src_ip": src, "src_port": 40001, "dest_ip": "10.30.0.5", "dest_port": 20000,
                       "proto": "TCP", "app_proto": "dnp3",
                       "dnp3": {"type": kind, "id": 0, "src": 3, "dst": 10,
                                "control": {"dir": True, "pri": True, "function_code": 4},
                                "application": {"control": {"fir": True, "fin": True, "con": False,
                                                            "uns": False, "sequence": 1},
                                                "function_code": fc, "objects": [], "complete": True}}})


def flow(src, port):
    return json.dumps({"event_type": "flow", "src_ip": src, "src_port": 51515, "dest_ip": PLC, "dest_port": port,
                       "proto": "TCP", "flow": {"bytes_toserver": 120, "bytes_toclient": 80}})


def ids_alert(signature, category="Attempted Information Leak", severity=2):
    return json.dumps({"event_type": "alert", "src_ip": HMI, "src_port": 50211, "dest_ip": PLC, "dest_port": 502,
                       "proto": "TCP", "alert": {"action": "allowed", "signature_id": 2014101, "rev": 3,
                                                 "signature": signature, "category": category,
                                                 "severity": severity}})


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture
def rules():  # per test: correlations keep state
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


def _alerts(decoders, rules, line):
    event, _ = decoders.decode_named("suricata", line)
    view = dict(event, raw_message=line, log_type="suricata", hostname="ot-sensor-1")
    return {m["title"].split(" [", 1)[0]: m["level"] for m in _LOOP.run_until_complete(rules.evaluate(view))}


def test_modbus_record_decodes(decoders):
    line = modbus(16, request={"write": {"address": 40001, "quantity": 2}})
    fields, name = decoders.decode_named("suricata", line)
    assert name == "suricata_eve_modbus"
    assert fields["event.dataset"] == "suricata.modbus" and fields["ot.protocol"] == "modbus"
    assert (fields["ot.function_code"], fields["ot.unit_id"], fields["ot.address"]) == ("16", "1", "40001")
    assert (fields["source.ip"], fields["destination.ip"], fields["destination.port"]) == (HMI, PLC, "502")
    assert fields["modbus.request.function_code"] == "Fc16"  # Suricata's own fields are kept


def test_a_record_forwarded_over_syslog_decodes_too(decoders, rules):
    # rsyslog imfile → syslog receiver keeps the RFC 3164 header in front of the JSON
    line = "Nov 15 01:02:03 ot-sensor-1 suricata: " + modbus(90)
    fields, name = decoders.decode_named("suricata", line)
    assert name == "suricata_eve_modbus" and fields["ot.function_code"] == "90"
    assert _alerts(decoders, rules, line).get("Modbus PLC Programming Command (UMAS)") == "critical"


def test_dnp3_record_decodes(decoders):
    fields, name = decoders.decode_named("suricata", dnp3(13))
    assert name == "suricata_eve_dnp3"
    assert (fields["ot.protocol"], fields["ot.message_type"], fields["ot.function_code"]) == ("dnp3", "request", "13")
    assert (fields["ot.source_address"], fields["ot.destination_address"]) == ("3", "10")


@pytest.mark.parametrize("line,title,level", [
    (modbus(6, src=OUTSIDER), "OT Control Command From The Internet", "critical"),
    (dnp3(5, src=OUTSIDER), "OT Control Command From The Internet", "critical"),
    (modbus(3, src=OUTSIDER), "OT Service Reached From The Internet", "high"),
    (flow(OUTSIDER, 102), "OT Service Reached From The Internet", "high"),
    (modbus(90), "Modbus PLC Programming Command (UMAS)", "critical"),
    (modbus(101), "Modbus User-Defined Function Code", "high"),
    (modbus(8, request={"diagnostic": {"raw": 4, "code": "ForceListenOnlyMode"}}),
     "Modbus Diagnostics Restart Or Listen-Only Command", "high"),
    (modbus(43, request={"mei": {"raw": 14, "code": "ReadDeviceId"}}), "Modbus Device Identification Query", "medium"),
    (modbus(17), "Modbus Device Identification Query", "medium"),
    (dnp3(13), "DNP3 Outstation Restart Or Stop Command", "critical"),
    (dnp3(18), "DNP3 Outstation Restart Or Stop Command", "critical"),
    (dnp3(21), "DNP3 Unsolicited Reporting Disabled", "high"),
    (dnp3(27), "DNP3 File Deleted On Outstation", "high"),
    (ids_alert("ET SCADA Modbus Write Multiple Registers Request"), "Suricata ICS/SCADA Signature Alert", "high"),
])
def test_ot_attacks_alert(decoders, rules, line, title, level):
    assert _alerts(decoders, rules, line).get(title) == level


@pytest.mark.parametrize("line", [
    modbus(3),                                   # HMI polling holding registers
    modbus(4),
    modbus(6),                                   # HMI writing a setpoint, inside the OT network
    modbus(16, request={"write": {"address": 40001, "quantity": 2}}),
    modbus(8, request={"diagnostic": {"raw": 0, "code": "ReturnQueryData"}}),  # diagnostics echo
    dnp3(1),                                     # SCADA master reading points
    dnp3(5),                                     # master operating a breaker, from inside
    dnp3(129, kind="response"),
    flow("10.20.0.60", 502),                     # internal flow to a PLC
    ids_alert("ET INFO Packet Statistics Anomaly", category="Generic Protocol Command Decode"),
])
def test_routine_ot_traffic_stays_quiet(decoders, rules, line):
    got = _alerts(decoders, rules, line)
    assert not [t for t in got if "OT " in t or "Modbus" in t or "DNP3" in t or "ICS" in t], got


def test_function_code_scan_is_one_correlated_alert(decoders, rules):
    seen = {}
    for fc in (1, 2, 3, 4, 5, 6):
        seen.update(_alerts(decoders, rules, modbus(fc)))
    assert seen.get("Modbus Function Code Scan") == "high"
    assert "Modbus Request" not in seen  # the base rule raises nothing itself


def test_polling_a_few_codes_is_not_a_scan(decoders, rules):
    seen = {}
    for _ in range(20):
        for fc in (3, 4, 16):
            seen.update(_alerts(decoders, rules, modbus(fc)))
    assert "Modbus Function Code Scan" not in seen


def test_the_demo_scenario_raises_each_expected_alert(decoders, rules):
    """scripts/ot-demo-replay.py, the pitch demo: every attack step alerts, the routine traffic does not."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("ot_demo", os.path.join(ROOT, "scripts/ot-demo-replay.py"))
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)

    by_step = []
    for what, records in demo.SCENARIO:
        got = {}
        for rec in records:
            line = demo.syslog_line(rec).split(">", 1)[1]  # the receiver drops <PRI>
            got.update(_alerts(decoders, rules, line))
        by_step.append((what, got))
    raised = {t: lvl for _, got in by_step for t, lvl in got.items()}
    assert raised == {
        "OT Service Reached From The Internet": "high",
        "Modbus Device Identification Query": "medium",
        "Modbus Function Code Scan": "high",
        "Modbus Unit ID Sweep": "high",
        "Modbus PLC Programming Command (UMAS)": "critical",
        "Modbus Diagnostics Restart Or Listen-Only Command": "high",
        "DNP3 Unsolicited Reporting Disabled": "high",
        "DNP3 Outstation Restart Or Stop Command": "critical",
        "DNP3 File Deleted On Outstation": "high",
        "OT Control Command From The Internet": "critical",
    }
    assert all(got == {} for what, got in by_step if "routine" in what)


def test_unit_id_sweep(decoders, rules):
    seen = {}
    for unit in range(1, 11):
        seen.update(_alerts(decoders, rules, modbus(3, unit=unit)))
    assert seen.get("Modbus Unit ID Sweep") == "high"
