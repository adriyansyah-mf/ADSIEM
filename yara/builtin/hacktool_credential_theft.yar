// Built-in ADSIEM rule pack: credential theft tools.

rule ADSIEM_HackTool_Mimikatz
{
    meta:
        description = "Mimikatz (or a build of it): credential dumping from LSASS, Kerberos tickets"
        severity = "critical"
        mitre = "T1003.001"
    strings:
        $c1 = "sekurlsa::logonpasswords" ascii wide nocase
        $c2 = "lsadump::sam" ascii wide nocase
        $c3 = "lsadump::dcsync" ascii wide nocase
        $c4 = "kerberos::golden" ascii wide nocase
        $c5 = "privilege::debug" ascii wide nocase
        $a1 = "gentilkiwi" ascii wide nocase
        $a2 = "mimikatz" ascii wide nocase
        $a3 = "kiwi_passwords" ascii wide
    condition:
        2 of ($c*) or (1 of ($c*) and 1 of ($a*))
}

rule ADSIEM_HackTool_LaZagne
{
    meta:
        description = "LaZagne password recovery tool: dumps browser, mail and system credentials"
        severity = "high"
        mitre = "T1555"
    strings:
        $a = "lazagne" ascii nocase
        $b1 = "softwares.browsers" ascii
        $b2 = "softwares.windows" ascii
        $b3 = "softwares.sysadmin" ascii
        $b4 = "config.write_output" ascii
    condition:
        $a and 2 of ($b*)
}

rule ADSIEM_Script_LSASS_Dump
{
    meta:
        description = "Script dumping LSASS memory with built-in tools (comsvcs.dll MiniDump, procdump -ma lsass)"
        severity = "critical"
        mitre = "T1003.001"
    strings:
        $comsvcs = "comsvcs.dll" ascii wide nocase
        $minidump = "MiniDump" ascii wide nocase
        $procdump = "procdump" ascii wide nocase
        $ma = "-ma" ascii wide
        $lsass = "lsass" ascii wide nocase
    condition:
        filesize < 1MB and $lsass and (($comsvcs and $minidump) or ($procdump and $ma))
}
