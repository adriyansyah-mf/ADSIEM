// Built-in ADSIEM rule pack: post-exploitation / C2 framework implants.

rule ADSIEM_C2_CobaltStrike_Beacon_Strings
{
    meta:
        description = "Cobalt Strike beacon (unencrypted or after unpacking): characteristic error and command strings"
        severity = "critical"
        mitre = "T1071.001"
    strings:
        $s1 = "could not spawn %s: %d" ascii
        $s2 = "could not open process token: %d (%u)" ascii
        $s3 = "Failed to impersonate token from %d (%u)" ascii
        $s4 = "%s as %s\\%s: %d" ascii
        $s5 = "beacon.dll" ascii
        $s6 = "beacon.x64.dll" ascii
        $s7 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii
    condition:
        3 of them
}

rule ADSIEM_C2_Meterpreter
{
    meta:
        description = "Metasploit Meterpreter payload or extension"
        severity = "critical"
        mitre = "T1059"
    strings:
        $m1 = "metsrv.dll" ascii wide
        $m2 = "ext_server_stdapi" ascii wide
        $m3 = "stdapi_sys_process_execute" ascii
        $m4 = "stdapi_fs_file_expand_path" ascii
        $m5 = "core_channel_open" ascii
        $m6 = "ReflectiveLoader" ascii
    condition:
        3 of them
}

rule ADSIEM_C2_Sliver_Implant
{
    meta:
        description = "Sliver implant (Go): its protobuf and package paths"
        severity = "critical"
        mitre = "T1071"
    strings:
        $p1 = "github.com/bishopfox/sliver" ascii
        $p2 = "sliverpb." ascii
        $p3 = "/implant/sliver/" ascii
        $p4 = "commonpb.Request" ascii
    condition:
        2 of them
}
