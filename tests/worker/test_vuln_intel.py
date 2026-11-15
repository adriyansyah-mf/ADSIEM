"""Vulnerability prioritisation, pure parts: CVSS 3.x base score, the
priority tiers, the KEV / EPSS / Microsoft CVRF parsers, which OSV ecosystem
a host is, and what a host row takes from an OSV record."""
import gzip

import pytest

from worker.vuln_intel import epss_rows, kev_rows, msrc_releases, msrc_rows
from worker.vuln_priority import cvss3_base, priority, severity_of
from worker.vuln_scan import compact_vuln, ecosystem, windows_build


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_matches_the_spec(vector, score):
    assert cvss3_base(vector) == score


def test_cvss_other_versions_and_junk_have_no_score():
    assert cvss3_base("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss3_base("CVSS:3.1/AV:X") is None and cvss3_base(None) is None
    assert [severity_of(s) for s in (9.8, 7.0, 5.0, 0.1, 0.0, None)] == ["critical", "high", "medium", "low", None, None]


def test_exploited_beats_likely_beats_severe():
    kev_medium = priority(True, 0.001, 5.0, "medium")
    likely = priority(False, 0.4, 6.5, "medium")
    severe_unlikely = priority(False, 0.0004, 9.8, "critical")
    assert [kev_medium[0], likely[0], severe_unlikely[0]] == ["critical", "high", "medium"]
    assert kev_medium[1] > likely[1] > severe_unlikely[1]
    assert priority(False, 0.02, 9.1, None)[0] == "high"       # severe and some chance
    assert priority(False, None, None, "high")[0] == "medium"  # vendor rating only
    assert priority(False, None, 3.1, "low")[0] == "low"


def test_kev_rows():
    rows = kev_rows({"vulnerabilities": [
        {"cveID": "CVE-2024-3400", "vulnerabilityName": "PAN-OS Command Injection", "dateAdded": "2024-04-12",
         "dueDate": "2024-04-19", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "not-a-cve"},
    ]})
    assert rows == [{"cve_id": "CVE-2024-3400", "kev": True, "kev_name": "PAN-OS Command Injection",
                     "kev_date_added": "2024-04-12", "kev_due_date": "2024-04-19", "kev_ransomware": True}]


def test_epss_rows_skip_the_model_line_and_bad_rows():
    raw = gzip.compress(b"#model_version:v2026.06.15,score_date:2026-11-15T12:03:04Z\n"
                        b"cve,epss,percentile\nCVE-2024-3400,0.94301,0.99912\nCVE-2024-1,bad,0.1\n")
    assert epss_rows(raw) == [{"cve_id": "CVE-2024-3400", "epss": 0.94301, "epss_percentile": 0.99912}]


# shaped like api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct
CVRF = {
    "ProductTree": {"FullProductName": [
        {"ProductID": "12389", "CPE": "cpe:2.3:o:microsoft:windows_11_24H2:10.0.26100.9974:*:*:*:*:*:arm64:*",
         "Value": "Windows 11 Version 24H2 for ARM64-based Systems"},
        {"ProductID": "12390", "CPE": "cpe:2.3:o:microsoft:windows_11_24H2:10.0.26100.9974:*:*:*:*:*:x64:*",
         "Value": "Windows 11 Version 24H2 for x64-based Systems"},
        {"ProductID": "11571", "CPE": "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.9487:*:*:*:*:*:*:*",
         "Value": "Windows Server 2019"},
        {"ProductID": "12436", "CPE": "cpe:2.3:o:microsoft:windows_server_2025:10.0.26100.33650:*:*:*:*:*:*:*",
         "Value": "Windows Server 2025"},
        {"ProductID": "22220", "CPE": "cpe:2.3:a:microsoft:.net_8.0:*:*:*:*:*:*:*:*", "Value": ".NET 8.0"},
    ]},
    "Vulnerability": [
        {"CVE": "CVE-2026-1001", "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
         "Threats": [{"Type": 3, "ProductID": ["12390"], "Description": {"Value": "Important"}},
                     {"Type": 3, "ProductID": ["11571"], "Description": {"Value": "Critical"}},
                     {"Type": 0, "ProductID": ["12390", "11571"], "Description": {"Value": "Elevation of Privilege"}}],
         "CVSSScoreSets": [{"BaseScore": 7.8, "ProductID": ["12390"]}, {"BaseScore": 8.8, "ProductID": ["11571"]}],
         "Remediations": [
             {"Type": 2, "ProductID": ["12389", "12390"], "FixedBuild": "10.0.26100.9711", "Description": {"Value": "5127648"}},
             {"Type": 2, "ProductID": ["12390"], "FixedBuild": "10.0.26100.9974", "Description": {"Value": "5132061"}},
             {"Type": 2, "ProductID": ["11571"], "FixedBuild": "10.0.17763.9487", "Description": {"Value": "5127700"}},
             # same build as Windows 11 24H2, its own UBR series
             {"Type": 2, "ProductID": ["12436"], "FixedBuild": "10.0.26100.33650", "Description": {"Value": "5126646"}},
             {"Type": 3, "ProductID": ["12390"], "SubType": "5127648"},
         ]},
        {"CVE": "CVE-2026-2002", "Title": {"Value": ".NET Denial of Service"},
         "Remediations": [{"Type": 2, "ProductID": ["22220"], "FixedBuild": "8.0.427", "Description": {"Value": "5133964"}}]},
    ],
}


def test_msrc_rows_one_per_cve_build_and_edition():
    rows = sorted(msrc_rows(CVRF, "2026-Oct"), key=lambda r: (r["build"], r["edition"]))
    assert [(r["cve_id"], r["build"], r["edition"], r["fixed_ubr"], r["kb"], r["severity"], r["cvss"]) for r in rows] == [
        ("CVE-2026-1001", "10.0.17763", "server", 9487, "KB5127700", "critical", 8.8),
        ("CVE-2026-1001", "10.0.26100", "client", 9974, "KB5132061", "high", 7.8),  # the later fix on that build wins
        ("CVE-2026-1001", "10.0.26100", "server", 33650, "KB5126646", None, None),
    ]
    assert rows[0]["impact"] == "Elevation of Privilege" and rows[0]["release"] == "2026-Oct"


def test_msrc_releases_newest_first():
    index = {"value": [
        {"ID": "2026-Sep", "InitialReleaseDate": "2026-09-08T07:00:00Z", "CurrentReleaseDate": "2026-11-15T01:43:07Z",
         "CvrfUrl": "https://x/2026-Sep"},
        {"ID": "2026-Oct", "InitialReleaseDate": "2026-10-13T07:00:00Z", "CvrfUrl": "https://x/2026-Oct"},
        {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-11T07:00:00Z", "CvrfUrl": "https://x/2026-Aug"},
    ]}
    assert [r["id"] for r in msrc_releases(index, 2)] == ["2026-Oct", "2026-Sep"]
    assert msrc_releases(index, 2)[1]["current"] == "2026-11-15T01:43:07Z"


@pytest.mark.parametrize("os_name,version,source,eco", [
    ("Ubuntu", "22.04", "dpkg", "Ubuntu:22.04:LTS"),
    ("Ubuntu", "23.10", "dpkg", "Ubuntu:23.10"),
    ("Debian GNU/Linux", "12", "dpkg", "Debian:12"),
    ("Alpine Linux", "3.19.1", "apk", "Alpine:v3.19"),
    ("Rocky Linux", "9.3", "rpm", "Rocky Linux:9"),
    ("AlmaLinux", "8.9", "rpm", "AlmaLinux:8"),
    ("Red Hat Enterprise Linux", "9.4", "rpm", "Red Hat"),
    ("Fedora Linux", "40", "rpm", None),         # not in OSV: no guess
    ("Linux Mint", "21.3", "dpkg", None),
    ("Microsoft Windows 11 Pro", "23H2", "windows", None),
])
def test_ecosystem(os_name, version, source, eco):
    assert ecosystem(os_name, version, source) == eco


def test_windows_build():
    assert windows_build("Windows 11 Pro", "10.0.26100.9711") == ("10.0.26100", 9711)
    assert windows_build("Windows Server 2012 R2 Standard", "6.3.9600.23470") == ("6.3.9600", 23470)
    assert windows_build("Ubuntu", "10.0.26100.9711") is None
    assert windows_build("Windows 11 Pro", "10.0.26100") is None


def test_compact_vuln_takes_the_hosts_own_release():
    record = {
        "id": "UBUNTU-CVE-2023-0464", "upstream": ["CVE-2023-0464"], "summary": "openssl: excessive resource use",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                     {"type": "Ubuntu", "score": "low"}],
        "affected": [
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:20.04:LTS"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-1ubuntu2.18"}]}]},
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.9"}]}]},
        ]}
    rec = compact_vuln(record, "Ubuntu:22.04:LTS", "openssl")
    assert rec == {"id": "UBUNTU-CVE-2023-0464", "cves": ["CVE-2023-0464"], "cvss": 7.5, "severity": "high",
                   "fixed": "3.0.2-0ubuntu1.9", "title": "openssl: excessive resource use"}
    # an advisory for several CVEs, no CVSS: the vendor rating stands
    rlsa = {"id": "RLSA-2022:7288", "upstream": ["CVE-2022-3602", "CVE-2022-3786"],
            "database_specific": {"severity": "Important"}, "affected": []}
    rec = compact_vuln(rlsa, "Rocky Linux:9", "openssl")
    assert rec["cves"] == ["CVE-2022-3602", "CVE-2022-3786"] and rec["severity"] == "high" and rec["fixed"] is None


def test_batches_stay_under_the_bind_parameter_limit():
    """asyncpg refuses more than 32767 parameters; Python-side column
    defaults are bound too, so the whole table's width counts."""
    from worker.models import CveIntel, MsrcFix
    from worker.vuln_intel import batches
    for model, width in ((CveIntel, 3), (MsrcFix, 10)):
        rows = [{f"c{i}": 0 for i in range(width)} for _ in range(20000)]
        chunks = list(batches(model, rows))
        assert sum(map(len, chunks)) == 20000
        assert max(map(len, chunks)) * len(model.__table__.columns) <= 32767
    assert list(batches(CveIntel, [])) == []
