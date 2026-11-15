"""Active Directory attack detections (rules/win_ad_*.yaml) on the Windows
agent's Security lines (agent/internal/winevent: EventID first, then System
fields, then every EventData field under its own name)."""
import asyncio
import glob
import os

import pytest
import yaml

from worker.decoder_engine import DecoderEngine
from worker.sigma_engine import SigmaEngine

ROOT = os.path.join(os.path.dirname(__file__), "../..")
_LOOP = asyncio.new_event_loop()  # not asyncio.run(): later modules need a current loop
ATTACKER = "::ffff:10.0.5.77"


def sec(event_id, **data):
    fields = {"Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
              "Computer": "DC01.corp.local", "RecordID": "1000", **data}
    return f"EventID={event_id} " + " ".join(f'{k}="{v}"' for k, v in fields.items())


def tgs(service, enc="0x17", ip=ATTACKER, status="0x0"):
    return sec(4769, IpAddress=ip, ServiceName=service, Status=status, TargetUserName="alice@CORP.LOCAL",
               TicketEncryptionType=enc, TicketOptions="0x40810000")


def tgt(user, preauth="0", enc="0x17"):
    return sec(4768, IpAddress=ATTACKER, PreAuthType=preauth, Status="0x0", TargetUserName=user,
               TicketEncryptionType=enc)


def replication(subject, guid="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"):
    return sec(4662, AccessMask="0x100", ObjectServer="DS", ObjectType="%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
               Properties=f"%%7688 {{{guid}}} {{19195a5b-6da0-11d0-afd3-00c04fd930c9}}",
               SubjectDomainName="CORP", SubjectUserName=subject)


def logon_failed(user, ip=ATTACKER):
    return sec(4625, IpAddress=ip, LogonType="3", Status="0xc000006d", TargetUserName=user,
               WorkstationName="KALI")


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
    event, _ = decoders.decode_named("windows_security", line)
    view = dict(event, raw_message=line, log_type="windows_security", hostname="DC01")
    return {m["title"].split(" [", 1)[0]: m["level"] for m in _LOOP.run_until_complete(rules.evaluate(view))}


@pytest.mark.parametrize("line,title,level", [
    (tgs("svc_sql"), "Kerberos Service Ticket Requested With RC4", "medium"),
    (tgt("svc_backup"), "AS-REP Roasting - Ticket Issued Without Pre-Authentication", "high"),
    (sec(4738, SubjectUserName="eve", TargetUserName="svc_backup",
         UserAccountControl="%%2096"), "Account Made AS-REP Roastable", "high"),
    (replication("eve"), "DCSync - Directory Replication By A Non-DC Account", "critical"),
    (replication("eve", "89e95b76-444d-4c62-991a-0facbeda640c"),
     "DCSync - Directory Replication By A Non-DC Account", "critical"),
    (sec(5136, AttributeLDAPDisplayName="servicePrincipalName", AttributeValue="http/fake.corp.local",
         ObjectClass="user", ObjectDN="CN=bob,CN=Users,DC=corp,DC=local", OperationType="%%14674",
         SubjectUserName="eve"), "SPN Added To A User Account", "medium"),
    (sec(4765, SidHistory="S-1-5-21-1-2-3-512", TargetUserName="eve"), "SID History Added To An Account", "high"),
    (sec(4794, SubjectUserName="eve", Workstation="DC01"), "Directory Services Restore Mode Password Changed", "high"),
])
def test_ad_attacks_alert(decoders, rules, line, title, level):
    assert _alerts(decoders, rules, line).get(title) == level


AD_TITLES = ("Kerberos", "Kerberoasting", "AS-REP", "DCSync", "Password Spraying", "SPN Added", "SID History", "DSRM")


@pytest.mark.parametrize("line", [
    tgs("svc_sql", enc="0x12"),                 # AES: the normal ticket
    tgs("WEB01$"),                              # computer account
    tgs("krbtgt"),
    tgs("svc_sql", status="0x1b"),              # failed request
    tgt("alice", preauth="2", enc="0x12"),      # pre-authenticated AES TGT
    replication("DC02$"),                       # a domain controller replicating
    replication("MSOL_a1b2c3d4e5"),             # Azure AD Connect sync account
    sec(4662, AccessMask="0x100", Properties="%%7688 {bf967aba-0de6-11d0-a285-00aa003049e2}",
        SubjectUserName="eve"),                 # other directory access
    sec(5136, AttributeLDAPDisplayName="description", ObjectClass="user", OperationType="%%14674",
        SubjectUserName="eve"),
    logon_failed("alice"),                      # one wrong password
])
def test_routine_domain_activity_stays_quiet(decoders, rules, line):
    got = _alerts(decoders, rules, line)
    assert not [t for t in got if any(k in t for k in AD_TITLES)], got


def test_kerberoasting_burst_is_correlated(decoders, rules):
    seen = {}
    for spn in ("svc_sql", "svc_web", "svc_backup", "svc_iis", "svc_sccm"):
        seen.update(_alerts(decoders, rules, tgs(spn)))
    assert seen.get("Kerberoasting - Many RC4 Service Tickets From One Source") == "high"
    assert seen.get("Kerberos Service Ticket Requested With RC4") == "medium"  # generate: true keeps each one


def test_password_spray_needs_many_accounts(decoders, rules):
    seen = {}
    for i in range(9):
        seen.update(_alerts(decoders, rules, logon_failed(f"user{i}")))
    assert "Password Spraying Against Domain Accounts" not in seen
    seen.update(_alerts(decoders, rules, sec(4771, IpAddress=ATTACKER, Status="0x18", TargetUserName="user9")))
    assert seen.get("Password Spraying Against Domain Accounts") == "high"
    assert "Windows Logon Failure" not in seen  # the base rule raises nothing itself


def test_spray_from_different_sources_is_not_one_spray(decoders, rules):
    seen = {}
    for i in range(12):
        seen.update(_alerts(decoders, rules, logon_failed(f"user{i}", ip=f"10.0.6.{i}")))
    assert "Password Spraying Against Domain Accounts" not in seen
