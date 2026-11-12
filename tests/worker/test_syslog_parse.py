"""Agentless syslog: frames become the raw_message the existing decoders expect."""
import ipaddress
from pathlib import Path

import pytest

from worker.decoder_engine import DecoderEngine, _parse_cef
from worker.syslog_parse import (MAX_MESSAGE_BYTES, SourceEntry, SourceTable, StreamFramer, normalize_ip,
                                 parse_syslog)

DECODERS = Path(__file__).resolve().parents[2] / "decoders"


def _engine(*names: str) -> DecoderEngine:
    engine = DecoderEngine()
    engine.load_from_yaml_list([(DECODERS / f"{n}.yaml").read_text() for n in names])
    return engine


# ── RFC 3164 / 5424 / headerless ──────────────────────────────────────────────

def test_rfc3164_keeps_the_file_shaped_line_and_reads_the_host():
    msg = parse_syslog(b"<38>May  1 10:00:00 web01 sshd[812]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
    assert msg.raw_message == "May  1 10:00:00 web01 sshd[812]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert msg.hostname == "web01"
    assert (msg.facility, msg.severity) == (4, 6)


def test_rfc3164_without_hostname_leaves_it_unset():
    msg = parse_syslog(b"<13>May  1 10:00:00 sshd[812]: hello")
    assert msg.hostname is None
    assert msg.raw_message == "May  1 10:00:00 sshd[812]: hello"


def test_rfc5424_is_rewritten_into_3164_shape():
    raw = (b'<34>1 2026-05-01T10:00:00.003Z web01 sshd 812 ID47 [exampleSDID@32473 iut="3" eventID="1011"] '
           b'\xef\xbb\xbfFailed password for root from 1.2.3.4 port 22 ssh2')
    msg = parse_syslog(raw)
    assert msg.hostname == "web01"
    assert msg.raw_message == "May  1 10:00:00 web01 sshd[812]: Failed password for root from 1.2.3.4 port 22 ssh2"


def test_rfc5424_nil_fields():
    msg = parse_syslog(b"<14>1 2026-05-01T10:00:00Z - - - - - plain text")
    assert msg.hostname is None
    assert msg.raw_message.endswith(" - plain text")


def test_fortigate_headerless_kv_loses_only_the_pri_and_decodes():
    raw = (b'<189>date=2026-05-01 time=10:00:00 devname="FGT-HQ" devid="FG100F" logid="0100032002" type="event" '
           b'subtype="system" level="alert" logdesc="Admin login failed" user="admin" srcip=203.0.113.9 '
           b'action="login" status="failed" msg="Administrator admin login failed from https(203.0.113.9)"')
    msg = parse_syslog(raw)
    assert msg.raw_message.startswith("date=2026-05-01")
    assert msg.hostname is None
    fields = _engine("fortigate_event").decode("fortigate_traffic", msg.raw_message)
    assert fields["source.ip"] == "203.0.113.9"
    assert fields["observer.hostname"] == "FGT-HQ"


def test_ssh_over_3164_and_5424_decodes_like_the_tailed_file():
    engine = DecoderEngine()
    engine.load_from_yaml_list([p.read_text() for p in sorted(DECODERS.glob("*.yaml"))])
    tailed = "May  1 10:00:00 web01 sshd[812]: Invalid user bob from 1.2.3.4 port 22"
    expected = engine.decode("linux_auth", tailed)
    assert expected.get("source.ip") == "1.2.3.4"
    for raw in (b"<38>" + tailed.encode(),
                b"<38>1 2026-05-01T10:00:00Z web01 sshd 812 - - Invalid user bob from 1.2.3.4 port 22"):
        assert engine.decode("linux_auth", parse_syslog(raw).raw_message) == expected


@pytest.mark.parametrize("raw", [b"", b"\n", b"<13>", b"<13>\r\n", b"\x00"])
def test_empty_frames_are_dropped(raw):
    assert parse_syslog(raw) is None


def test_invalid_utf8_and_oversize_never_raise():
    msg = parse_syslog(b"<13>\xff\xfe bad " + b"x" * (MAX_MESSAGE_BYTES * 2))
    assert msg is not None and len(msg.raw_message.encode()) <= MAX_MESSAGE_BYTES * 2


# ── TCP framing ───────────────────────────────────────────────────────────────

def test_newline_framing_across_chunks():
    f = StreamFramer()
    assert f.feed(b"<13>one\n<13>tw") == [b"<13>one"]
    assert f.feed(b"o\n\n<13>three\x00") == [b"<13>two", b"<13>three"]
    assert f.flush() == []


def test_octet_counting_across_chunks():
    f = StreamFramer()
    m1, m2 = b"<13>hello world", b"<14>second\nline"
    stream = b"%d %s%d %s" % (len(m1), m1, len(m2), m2)
    assert f.feed(stream[:7]) == []
    assert f.feed(stream[7:20]) == [m1]
    assert f.feed(stream[20:]) == [m2]


def test_a_line_starting_with_digits_is_not_octet_counted():
    f = StreamFramer()
    assert f.feed(b"2026 is not a length\n") == [b"2026 is not a length"]


def test_oversized_line_is_cut_and_the_rest_skipped():
    f = StreamFramer(max_bytes=16)
    frames = f.feed(b"<13>" + b"a" * 40)
    assert frames == [b"<13>" + b"a" * 12]
    assert f.feed(b"aaaa\n<13>next\n") == [b"<13>next"]


def test_oversized_octet_frame_is_cut_and_the_rest_skipped():
    f = StreamFramer(max_bytes=8)
    body = b"<13>" + b"z" * 20
    assert f.feed(b"%d %s" % (len(body), body[:10])) == [body[:8]]
    assert f.feed(body[10:] + b"\n<13>ok\n") == [b"<13>ok"]


def test_flush_returns_an_unterminated_last_message():
    f = StreamFramer()
    assert f.feed(b"<13>last") == []
    assert f.flush() == [b"<13>last"]


# ── sender lookup ─────────────────────────────────────────────────────────────

def _entry(name, cidr, group="blue"):
    return SourceEntry(name, name, group, "cef", ipaddress.ip_network(cidr))


def test_most_specific_cidr_wins_and_unknown_is_none():
    table = SourceTable([_entry("lan", "10.0.0.0/16"), _entry("fw", "10.0.5.1/32", "red")])
    assert table.lookup("10.0.5.1").name == "fw"
    assert table.lookup("10.0.9.9").name == "lan"
    assert table.lookup("192.168.1.1") is None
    assert table.lookup("not-an-ip") is None


def test_ipv4_mapped_ipv6_peer_matches_ipv4_source():
    assert normalize_ip("::ffff:10.0.5.1") == "10.0.5.1"
    assert SourceTable([_entry("fw", "10.0.5.1/32")]).lookup("::ffff:10.0.5.1").name == "fw"


def test_ipv6_sources():
    table = SourceTable([_entry("v6", "2001:db8::/64")])
    assert table.lookup("2001:db8::7").name == "v6"
    assert table.lookup("2001:db9::7") is None


# ── CEF ───────────────────────────────────────────────────────────────────────

CEF = (r"May  1 10:00:00 pa01 CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|Spyware\|C2 beacon|8|"
       r"src=10.0.0.5 spt=51515 dst=198.51.100.7 dpt=443 suser=corp\\alice act=reset-both "
       r"msg=C2 traffic detected a\=b request=https://evil.example/x?a=1 cs1Label=Rule cs1=block-c2")


def test_cef_header_escapes_and_extension_values_with_spaces():
    f = _parse_cef(CEF)
    assert f["device_vendor"] == "Palo Alto Networks"
    assert f["name"] == "Spyware|C2 beacon"
    assert f["severity"] == "8"
    assert f["suser"] == "corp\\alice"
    assert f["msg"] == "C2 traffic detected a=b"
    assert f["request"] == "https://evil.example/x?a=1"
    assert f["cs1"] == "block-c2"


def test_cef_needs_a_complete_header():
    assert _parse_cef("CEF:0|vendor|product") == {}
    assert _parse_cef("no cef here") == {}


def test_cef_generic_decoder_maps_to_ecs():
    fields = _engine("cef_generic").decode("cef", CEF)
    assert fields["source.ip"] == "10.0.0.5"
    assert fields["destination.port"] == "443"
    assert fields["user.name"] == "corp\\alice"
    assert fields["observer.product"] == "PAN-OS"
    assert fields["event.action"] == "reset-both"
    assert fields["rule.name"] == "Spyware|C2 beacon"
    assert fields["event.dataset"] == "cef"
