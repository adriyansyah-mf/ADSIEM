// Built-in ADSIEM rule pack: ransomware notes and pre-encryption scripts.

rule ADSIEM_Ransomware_Note
{
    meta:
        description = "Ransom note: files said to be encrypted, with payment and contact instructions"
        severity = "critical"
        mitre = "T1486"
    strings:
        $e1 = "your files have been encrypted" ascii wide nocase
        $e2 = "all your files are encrypted" ascii wide nocase
        $e3 = "your network has been penetrated" ascii wide nocase
        $e4 = "files are encrypted" ascii wide nocase
        $p1 = "bitcoin" ascii wide nocase
        $p2 = ".onion" ascii wide nocase
        $p3 = "tor browser" ascii wide nocase
        $p4 = "decryptor" ascii wide nocase
        $p5 = "private key" ascii wide nocase
        $p6 = "do not rename" ascii wide nocase
    condition:
        filesize < 256KB and 1 of ($e*) and 2 of ($p*)
}

rule ADSIEM_Ransomware_Recovery_Inhibition_Script
{
    meta:
        description = "Script deleting shadow copies, backups and boot recovery together, as ransomware does before encrypting"
        severity = "critical"
        mitre = "T1490"
    strings:
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "vssadmin.exe delete shadows" ascii wide nocase
        $w1 = "shadowcopy delete" ascii wide nocase
        $w2 = "Win32_ShadowCopy" ascii wide nocase
        $b1 = "wbadmin delete catalog" ascii wide nocase
        $b2 = "recoveryenabled no" ascii wide nocase
        $b3 = "bootstatuspolicy ignoreallfailures" ascii wide nocase
    condition:
        filesize < 5MB and 2 of them
}
