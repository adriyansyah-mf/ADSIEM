// Built-in ADSIEM rule pack: script loaders and reverse shells.

rule ADSIEM_Script_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradle (IEX of a downloaded string), as droppers and loaders use"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $iex = /(IEX|Invoke-Expression)\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient\)?\s*\.\s*Download(String|Data)\s*\(/ nocase
        $iwr = /(IEX|Invoke-Expression)\s*\(?\s*\(?\s*(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s/ nocase
    condition:
        filesize < 2MB and any of them
}

rule ADSIEM_Script_PowerShell_AMSI_Bypass
{
    meta:
        description = "PowerShell AMSI bypass: amsiInitFailed set through reflection"
        severity = "high"
        mitre = "T1562.001"
    strings:
        $a1 = "AmsiUtils" ascii wide nocase
        $a2 = "amsiInitFailed" ascii wide nocase
        $r1 = "GetField" ascii wide nocase
        $r2 = "NonPublic" ascii wide nocase
    condition:
        filesize < 2MB and $a1 and $a2 and 1 of ($r*)
}

rule ADSIEM_Script_Reverse_Shell_OneLiner
{
    meta:
        description = "Reverse shell one-liner (bash /dev/tcp, nc -e, socat exec, python/perl socket + pty)"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $b = /bash\s+-i\s+>&?\s*\/dev\/tcp\/[0-9a-zA-Z.\-]{3,64}\/[0-9]{1,5}/
        $n = /\bnc(at)?\s+(-[a-z]*e|--exec)\s+\/bin\/(ba)?sh/
        $s = /socat\s+.{0,40}exec:['"]?\/bin\/(ba)?sh/ nocase
        $p1 = "socket.socket(socket.AF_INET" ascii
        $p2 = "pty.spawn(" ascii
        $p3 = "subprocess.call([\"/bin/sh\"" ascii
        $pl = /perl\s+-e\s+['"]use Socket;/
    condition:
        filesize < 1MB and ($b or $n or $s or $pl or ($p1 and ($p2 or $p3)))
}
