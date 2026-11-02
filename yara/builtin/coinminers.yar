// Built-in ADSIEM rule pack: cryptocurrency miners.

rule ADSIEM_CoinMiner_XMRig
{
    meta:
        description = "XMRig (or a fork): Monero miner, binary or its config"
        severity = "high"
        mitre = "T1496"
    strings:
        $x1 = "xmrig" ascii wide nocase
        $x2 = "--donate-level" ascii wide
        $x3 = "\"donate-level\"" ascii
        $x4 = "randomx" ascii wide nocase
        $x5 = "cryptonight" ascii wide nocase
        $pool = "stratum+tcp://" ascii wide nocase
        $pool2 = "stratum+ssl://" ascii wide nocase
    condition:
        ($x1 and 1 of ($x2, $x3, $x4, $x5)) or (1 of ($pool*) and 2 of ($x*))
}

rule ADSIEM_CoinMiner_Dropper_Script
{
    meta:
        description = "Shell script that downloads and starts a miner, often killing competing miners first"
        severity = "high"
        mitre = "T1496"
    strings:
        $sh = "#!/" ascii
        $dl1 = "curl " ascii
        $dl2 = "wget " ascii
        $m1 = "xmrig" ascii nocase
        $m2 = "stratum+tcp://" ascii nocase
        $k1 = "pkill -f" ascii
        $k2 = "kinsing" ascii nocase
        $k3 = "kdevtmpfsi" ascii nocase
    condition:
        filesize < 512KB and $sh at 0 and 1 of ($dl*) and 1 of ($m*) and 1 of ($k*)
}
