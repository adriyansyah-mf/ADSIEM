"""JSON decoder type, and the Suricata EVE / Zeek decoders and rules built on it.
Lines are real-world shaped samples: eve.json as Suricata 7 writes it, Zeek's
JSON logs (LogAscii::use_json=T), and the same forwarded over syslog."""
import asyncio
import glob
import json
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine
from worker.syslog_parse import parse_syslog

ROOT = os.path.join(os.path.dirname(__file__), "../..")


def _load(pattern):
    return [open(p).read() for p in sorted(glob.glob(os.path.join(ROOT, pattern)))]


@pytest.fixture(scope="module")
def decoders():
    dec = DecoderEngine()
    dec.load_from_yaml_list(sorted(_load("decoders/*.yaml"), key=lambda c: yaml.safe_load(c).get("priority", 100)))
    return dec


@pytest.fixture(scope="module")
def rules():
    sig = SigmaEngine()
    sig.load_from_yaml_list(_load("rules/*.yaml"))
    assert not sig.load_errors, sig.load_errors
    return sig


EVE_ALERT = json.dumps({
    "timestamp": "2026-11-12T08:01:02.345678+0700", "flow_id": 1234567890123456, "in_iface": "eth0",
    "event_type": "alert", "src_ip": "10.0.5.23", "src_port": 49822, "dest_ip": "185.199.1.7", "dest_port": 443,
    "proto": "TCP", "app_proto": "tls", "host": "ids-01",
    "alert": {"action": "allowed", "gid": 1, "signature_id": 2027865, "rev": 3,
              "signature": "ET MALWARE Cobalt Strike Beacon Observed", "category": "A Network Trojan was detected",
              "severity": 1},
})
EVE_DNS_V2 = json.dumps({"event_type": "dns", "src_ip": "10.0.5.23", "src_port": 51000, "dest_ip": "10.0.0.53",
                         "dest_port": 53, "proto": "UDP",
                         "dns": {"type": "query", "id": 4711, "rrname": "evil.example", "rrtype": "A"}})
EVE_DNS_V3 = json.dumps({"event_type": "dns", "src_ip": "10.0.5.23", "dest_ip": "10.0.0.53", "proto": "UDP",
                         "dns": {"version": 3, "type": "request", "queries": [{"rrname": "evil.example",
                                                                                "rrtype": "TXT"}]}})
EVE_HTTP = json.dumps({"event_type": "http", "src_ip": "10.0.5.23", "dest_ip": "93.184.216.34", "dest_port": 80,
                       "http": {"hostname": "example.com", "url": "/a%20b?x=1", "http_method": "GET", "status": 200,
                                "http_user_agent": "curl/8.5"}})
EVE_FLOW = json.dumps({"event_type": "flow", "src_ip": "10.0.5.23", "dest_ip": "8.8.8.8", "proto": "UDP",
                       "flow": {"bytes_toserver": 120, "bytes_toclient": 480}})
ZEEK_CONN = json.dumps({"ts": 1794470000.1, "uid": "CHhAvVGS1DHFjwGM9", "id.orig_h": "10.0.5.23", "id.orig_p": 49822,
                        "id.resp_h": "185.199.1.7", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                        "duration": 1.25, "orig_bytes": 517, "resp_bytes": 4096, "conn_state": "SF"})
ZEEK_DNS = json.dumps({"ts": 1794470000.2, "uid": "C1", "id.orig_h": "10.0.5.23", "id.orig_p": 51000,
                       "id.resp_h": "10.0.0.53", "id.resp_p": 53, "proto": "udp", "query": "evil.example",
                       "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["185.199.1.7"]})
ZEEK_NOTICE = json.dumps({"ts": 1794470000.3, "note": "Scan::Port_Scan", "msg": "10.0.5.66 scanned at least 15 "
                          "unique ports of host 10.0.5.10 in 0m3s", "src": "10.0.5.66", "dst": "10.0.5.10",
                          "id.orig_h": "10.0.5.66"})


def test_suricata_alert(decoders):
    fields, name = decoders.decode_named("suricata", EVE_ALERT)
    assert name == "suricata_eve_alert"
    assert fields["source.ip"] == "10.0.5.23" and fields["destination.port"] == "443"
    assert fields["rule.name"] == "ET MALWARE Cobalt Strike Beacon Observed"
    assert fields["rule.id"] == "2027865" and fields["event.severity"] == "1"
    assert fields["event.kind"] == "alert" and fields["event.dataset"] == "suricata.alert"
    assert fields["event.id"] == "1234567890123456"          # big ints stay exact


@pytest.mark.parametrize("line,rtype", [(EVE_DNS_V2, "A"), (EVE_DNS_V3, "TXT")])
def test_suricata_dns_both_eve_layouts(decoders, line, rtype):
    fields, name = decoders.decode_named("suricata", line)
    assert name == "suricata_eve_dns"
    assert fields["dns.question.name"] == "evil.example" and fields["dns.question.type"] == rtype


def test_suricata_http_is_url_decoded_like_other_web_logs(decoders):
    fields, _ = decoders.decode_named("suricata", EVE_HTTP)
    assert fields["url.domain"] == "example.com" and fields["url.path"] == "/a b?x=1"
    assert fields["url.original"] == "/a%20b?x=1" and fields["http.response.status_code"] == "200"


def test_other_eve_records_fall_back_to_the_generic_decoder(decoders):
    fields, name = decoders.decode_named("suricata", EVE_FLOW)
    assert name == "suricata_eve_generic" and fields["event.action"] == "flow"
    assert fields["source.bytes"] == "120" and fields["destination.bytes"] == "480"


def test_eve_forwarded_over_syslog(decoders):
    msg = parse_syslog(f"<134>Nov 12 08:01:02 ids-01 suricata[812]: {EVE_ALERT}".encode())
    fields, name = decoders.decode_named("suricata", msg.raw_message)
    assert name == "suricata_eve_alert" and fields["rule.id"] == "2027865"


def test_zeek_logs_are_told_apart_by_their_fields(decoders):
    conn, name = decoders.decode_named("zeek", ZEEK_CONN)
    assert name == "zeek_conn" and conn["source.ip"] == "10.0.5.23" and conn["destination.port"] == "443"
    assert conn["network.protocol"] == "ssl" and conn["event.dataset"] == "zeek.conn"
    assert conn["id.orig_h"] == "10.0.5.23" and conn["conn_state"] == "SF"   # Zeek's own names kept
    dns, name = decoders.decode_named("zeek", ZEEK_DNS)
    assert name == "zeek_dns" and dns["dns.question.name"] == "evil.example"
    assert dns["answers"] == '["185.199.1.7"]'
    notice, name = decoders.decode_named("zeek", ZEEK_NOTICE)
    assert name == "zeek_notice" and notice["rule.name"] == "Scan::Port_Scan" and notice["event.kind"] == "alert"


@pytest.mark.parametrize("line", ["", "not json at all", "{broken", "[1,2,3]", '{"event_type": "alert"'])
def test_bad_json_never_raises(decoders, line):
    assert decoders.decode_named("suricata", line) == ({}, None)


def _titles(decoders, rules, log_type, line):
    event, _ = decoders.decode_named(log_type, line)
    view = dict(event, raw_message=line, log_type=log_type, hostname="ids-01")
    return {m["title"] for m in asyncio.run(rules.evaluate(view))}


@pytest.mark.parametrize("severity,title", [
    (1, "Suricata IDS Alert (high-severity)"),
    (2, "Suricata IDS Alert (medium-severity)"),
    (3, "Suricata IDS Alert (low-severity)"),
])
def test_suricata_alerts_become_siem_alerts_by_severity(decoders, rules, severity, title):
    line = EVE_ALERT.replace('"severity": 1', f'"severity": {severity}')
    titles = _titles(decoders, rules, "suricata", line)
    assert title in titles and not any(t.startswith("Suricata IDS Alert") and t != title for t in titles)


def test_suricata_telemetry_raises_no_ids_alert(decoders, rules):
    for line in (EVE_DNS_V2, EVE_HTTP, EVE_FLOW):
        assert not any(t.startswith("Suricata IDS Alert") for t in _titles(decoders, rules, "suricata", line))


def test_zeek_notice_becomes_an_alert(decoders, rules):
    assert "Zeek Notice" in _titles(decoders, rules, "zeek", ZEEK_NOTICE)
    assert "Zeek Notice" not in _titles(decoders, rules, "zeek", ZEEK_CONN)


def test_engine_conditions_and_paths():
    dec = DecoderEngine()
    dec.load_from_yaml_list(["""
name: t
log_type: x
type: json
when: {kind: [a, b], "meta.ok": true, "list.0": "*"}
fields:
  out: [missing.path, nested.value]
  flat: "dotted.key"
"""])
    good = json.dumps({"kind": "b", "meta": {"ok": True}, "list": [0], "nested": {"value": 7}, "dotted.key": "v"})
    assert dec.decode("x", good) == {"out": "7", "flat": "v"}
    for bad in ({"kind": "c"}, {"kind": "a", "meta": {"ok": False}, "list": [0]}, {"kind": "a", "meta": {"ok": True}}):
        assert dec.decode("x", json.dumps(bad)) == {}
