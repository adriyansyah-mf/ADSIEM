// Built-in ADSIEM rule pack: web shells (PHP, ASP.NET, JSP).

rule ADSIEM_Webshell_PHP_Eval_Request
{
    meta:
        description = "PHP web shell: code from the request evaluated (eval/assert of $_POST/$_GET/$_REQUEST, often base64- or gz-decoded)"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $php = "<?php" ascii nocase
        $e1 = /(eval|assert)\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)?\s*\(?\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $e2 = /(system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(POST|GET|REQUEST)\s*\[/ nocase
        $e3 = /preg_replace\s*\(\s*['"].{1,20}\/e['"]\s*,\s*\$_(POST|GET|REQUEST)/ nocase
    condition:
        filesize < 2MB and $php and any of ($e*)
}

rule ADSIEM_Webshell_PHP_Known_Families
{
    meta:
        description = "Well-known PHP web shells (c99, r57, b374k, WSO, P.A.S.)"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $f1 = "c99shell" ascii nocase
        $f2 = "r57shell" ascii nocase
        $f3 = "b374k" ascii nocase
        $f4 = "WSO " ascii
        $f5 = "FilesMan" ascii
        $f6 = "P.A.S. Fork" ascii
        $php = "<?" ascii
    condition:
        filesize < 2MB and $php and 2 of ($f*)
}

rule ADSIEM_Webshell_ASPX_China_Chopper_Style
{
    meta:
        description = "ASP.NET web shell: request content evaluated or run as a process (China Chopper and look-alikes)"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $page = "<%@ Page" ascii nocase
        $j = /eval\s*\(\s*Request(\.Item)?\s*\[/ nocase
        $p1 = "Process.Start" ascii nocase
        $p2 = "cmd.exe" ascii nocase
        $p3 = /Request(\.Form|\.QueryString)?\s*\[/ nocase
    condition:
        filesize < 1MB and $page and ($j or ($p1 and $p2 and $p3))
}

rule ADSIEM_Webshell_JSP_Runtime_Exec
{
    meta:
        description = "JSP web shell: a request parameter run through Runtime.exec"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $exec = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter\s*\(/ nocase
    condition:
        filesize < 1MB and $exec
}
