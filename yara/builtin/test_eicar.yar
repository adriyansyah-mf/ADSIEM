// Built-in ADSIEM rule pack. Written for ADSIEM (no third-party rules), MIT,
// compiled by the agent's engine in CI (agent/internal/yara/builtin_test.go).

rule ADSIEM_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file: proves on-access scanning works, harmless"
        severity = "low"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 and filesize < 256
}
