package ransomguard

import (
	"encoding/base64"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Precursor rules: what ransomware runs before it encrypts (backups and
// shadow copies deleted, boot recovery turned off, a vulnerable driver
// loaded, security products stopped). Matching is on the command line,
// lower case, command by command (cmd /c "a & b" is two commands), so the
// shell that wraps a command matches as early as the command itself.
//
// A critical precursor is enough on its own. A score precursor (stopping or
// weakening a security product) needs scoreNeeded distinct indicators from
// the same initiator within scoreWindow.

// precursor categories (the Precursor= field).
const (
	catShadow   = "shadow_delete"
	catBackup   = "backup_delete"
	catBoot     = "boot_tamper"
	catBYOVD    = "byovd"
	catDefense  = "defense_tamper"
	catSnapshot = "snapshot_delete"
	catModule   = "kernel_module"
)

// hit is a matched command line.
type hit struct {
	category string
	// score lists the distinct indicators of a score hit (nil: critical).
	score []string
	// driver is a BYOVD driver path (lower case, forward slashes); when
	// inDrivers is set it is in the system driver directory, and the hit
	// stands only if the initiator dropped it there or runs from a
	// user-writable directory (decided once the initiator is known).
	driver    string
	inDrivers bool
	// revert holds bcdedit argument lists that undo a boot change, and
	// reverted their names (the Reverted= field).
	revert   [][]string
	reverted []string
}

func (h *hit) critical(cat string) {
	if h.category == "" || h.score != nil {
		h.category, h.score = cat, nil
	}
}

func (h *hit) addScore(key string) {
	if h.category != "" && h.score == nil {
		return // already critical
	}
	h.category = catDefense
	for _, k := range h.score {
		if k == key {
			return
		}
	}
	h.score = append(h.score, key)
}

func (h *hit) addRevert(name string, args ...string) {
	j := strings.Join(args, " ")
	for _, r := range h.revert {
		if strings.Join(r, " ") == j {
			return
		}
	}
	h.revert = append(h.revert, args)
	h.reverted = append(h.reverted, name)
}

func (h *hit) result() *hit {
	if h.category == "" {
		return nil
	}
	return h
}

// commands splits a command line into its commands, each into words: lower
// case, cmd's ^ escapes dropped, split at & | ; and line breaks.
func commands(cmdline string) [][]string {
	s := strings.ToLower(strings.ReplaceAll(cmdline, "^", ""))
	var out [][]string
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '&' || r == '|' || r == ';' || r == '\n' || r == '\r'
	}) {
		if w := words(seg); len(w) > 0 {
			out = append(out, w)
		}
	}
	return out
}

// words splits one command at blanks. A quoted word stays whole (a path
// with spaces) unless it is itself a command line (cmd /c "vssadmin ...":
// its first word is not a path), which is split too. Unbalanced quotes
// (a split inside cmd /c "...") are dropped.
func words(seg string) []string {
	if strings.Count(seg, `"`)%2 == 1 {
		seg = strings.ReplaceAll(seg, `"`, " ")
	}
	var out []string
	var cur strings.Builder
	inQ, quoted := false, false
	flush := func() {
		w := cur.String()
		cur.Reset()
		if w == "" && !quoted {
			return
		}
		q := quoted
		quoted = false
		if f := strings.Fields(w); q && len(f) > 1 && !strings.ContainsAny(f[0], `\/:`) {
			out = append(out, words(w)...)
			return
		}
		out = append(out, w)
	}
	for _, r := range seg {
		switch {
		case r == '"':
			inQ = !inQ
			quoted = true
		case !inQ && (r == ' ' || r == '\t'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// toolName is a word's program name: no directory, no .exe.
func toolName(w string) string {
	return strings.TrimSuffix(base(w), ".exe")
}

func hasWord(args []string, w string) bool {
	for _, a := range args {
		if a == w {
			return true
		}
	}
	return false
}

// next is the word after w in args, or "".
func next(args []string, w string) string {
	for i, a := range args {
		if a == w && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// value is an sc-style option's value: "key= v" or "key=v".
func value(args []string, key string) string {
	for i, a := range args {
		if a == key && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, key); ok && v != "" {
			return v
		}
	}
	return ""
}

// encoded finds PowerShell's -EncodedCommand (any abbreviation of it) and
// its base64 UTF-16 script.
var encoded = regexp.MustCompile(`(?i)\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["']?([A-Za-z0-9+/=]{8,})`)

func decodeEncoded(cmdline string) string {
	var out []string
	for _, m := range encoded.FindAllStringSubmatch(cmdline, 4) {
		b, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil || len(b)%2 != 0 {
			continue
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		out = append(out, string(utf16.Decode(u)))
	}
	return strings.Join(out, "\n")
}

// securityTargets are security products' services and processes (lower
// case, no .exe), the agent's own included; securityPrefixes match vendor
// families.
var securityTargets = map[string]bool{
	"windefend": true, "sense": true, "securityhealthservice": true, "wscsvc": true, "wdnissvc": true,
	"mpksldrv": true, "nissrv": true, "wdboot": true, "wdfilter": true, "wdnisdrv": true, "msmpeng": true,
	"mssense": true, "mpdefendercoreservice": true, "mpcmdrun": true,
	"siemagent": true, "siem-agent": true,
	"avp": true, "avpsus": true, "kav": true, "kavfs": true, "kavfsgt": true, "klnagent": true,
	"bdss": true, "vsserv": true, "bdagent": true, "epsecurityservice": true, "epintegrationservice": true,
	"epredline": true, "ekrn": true, "egui": true, "sepmasterservice": true, "ccsvchst": true,
	"tmlisten": true, "ntrtscan": true, "ds_agent": true, "amsp": true, "wrsvc": true,
	"psanhost": true, "cmdagent": true, "savservice": true, "hmpalert": true,
}

var securityPrefixes = []string{"avast", "avg", "bitdefender", "kaspersky", "mbam", "malwarebytes", "drweb",
	"sophos", "mcafee", "mfe", "symantec", "norton", "sentinel", "csfalcon", "cylance", "cbdefense",
	"carbonblack", "trendmicro", "webroot", "eset", "f-secure", "fsecure", "panda", "comodo",
	"elastic-agent", "elastic-endpoint", "wazuh", "ossec", "sysmon", "qualys", "tanium"}

func securityTarget(t string) bool {
	t = strings.TrimSuffix(strings.Trim(t, `"'`), ".exe")
	if securityTargets[t] {
		return true
	}
	for _, p := range securityPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func targetKey(t string) string { return strings.TrimSuffix(strings.Trim(t, `"'`), ".exe") }

// defenderValues are the registry values that turn Defender off.
var defenderValues = map[string]bool{"disableantispyware": true, "disableantivirus": true,
	"disablerealtimemonitoring": true, "disablebehaviormonitoring": true, "disableioavprotection": true,
	"disableonaccessprotection": true, "disablescanonrealtimeenable": true}

func falseValue(v string) bool {
	switch strings.Trim(v, `"'`) {
	case "$false", "0", "false", "0x0", "0x00000000":
		return true
	}
	return false
}

// tinyShadowStorage: a /maxsize under 1 GB (ransomware shrinks the storage
// to purge the copies); percentages and UNBOUNDED are an admin's sizing.
func tinyShadowStorage(v string) bool {
	if v == "" || strings.HasSuffix(v, "%") || v == "unbounded" {
		return false
	}
	mult := map[string]float64{"tb": 1 << 40, "gb": 1 << 30, "mb": 1 << 20, "kb": 1 << 10, "b": 1, "": 1}
	num := strings.TrimRight(v, "abcdefghijklmnopqrstuvwxyz")
	unit := v[len(num):]
	m, ok := mult[unit]
	n, err := strconv.ParseFloat(num, 64)
	if !ok || err != nil {
		return false
	}
	return n*m < 1<<30
}

// classifyWindows matches a Windows process start's command line.
func classifyWindows(cmdline string) *hit {
	text := cmdline
	if d := decodeEncoded(cmdline); d != "" {
		text += "\n" + d
	}
	h := &hit{}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "win32_shadowcopy") && strings.Contains(lower, "delete") ||
		strings.Contains(lower, "win32_shadowcopy") && (strings.Contains(lower, "remove-ciminstance") || strings.Contains(lower, "remove-wmiobject")) {
		h.critical(catShadow)
	}
	for _, cmd := range commands(text) {
		for i, w := range cmd {
			windowsCommand(h, toolName(w), cmd[i+1:])
		}
	}
	return h.result()
}

func windowsCommand(h *hit, tool string, args []string) {
	switch tool {
	case "vssadmin":
		if next(args, "delete") == "shadows" && !hasWord(args, "/oldest") {
			h.critical(catShadow)
		}
		if next(args, "resize") == "shadowstorage" {
			for _, a := range args {
				if v, ok := strings.CutPrefix(a, "/maxsize="); ok && tinyShadowStorage(v) {
					h.critical(catShadow)
				}
			}
		}
	case "wmic":
		if hasWord(args, "shadowcopy") && hasWord(args, "delete") {
			h.critical(catShadow)
		}
	case "wbadmin":
		switch next(args, "delete") {
		case "catalog":
			h.critical(catBackup)
		case "systemstatebackup", "backup":
			keep := false
			for _, a := range args {
				a = strings.TrimLeft(a, "-/")
				if v, ok := strings.CutPrefix(a, "keepversions:"); ok {
					n, err := strconv.Atoi(v)
					keep = keep || err == nil && n > 0
				}
				keep = keep || a == "deleteoldest" || strings.HasPrefix(a, "version:")
			}
			if !keep {
				h.critical(catBackup)
			}
		}
	case "bcdedit":
		if !hasWord(args, "/set") && !hasWord(args, "-set") {
			return
		}
		id := "{current}" // bcdedit's default entry when none is named
		for _, a := range args {
			if strings.HasPrefix(a, "{") {
				id = a
				break
			}
		}
		for j, a := range args {
			v := ""
			if j+1 < len(args) {
				v = args[j+1]
			}
			switch a {
			case "recoveryenabled":
				if v == "no" || v == "off" || falseValue(v) {
					h.critical(catBoot)
					h.addRevert("recoveryenabled", "/set", id, "recoveryenabled", "yes")
				}
			case "bootstatuspolicy":
				if strings.HasPrefix(v, "ignore") {
					h.critical(catBoot)
					h.addRevert("bootstatuspolicy", "/set", id, "bootstatuspolicy", "displayallfailures")
				}
			case "safeboot", "safemode":
				h.critical(catBoot)
				h.addRevert("safeboot", "/deletevalue", id, "safeboot")
			}
		}
	case "sc":
		if len(args) == 0 {
			return
		}
		switch args[0] {
		case "create":
			t := value(args, "type=")
			if bin := value(args, "binpath="); (t == "kernel" || t == "filesys") && bin != "" {
				byovd(h, bin)
			}
		case "stop", "delete":
			if len(args) > 1 && securityTarget(args[1]) {
				h.addScore(args[0] + ":" + targetKey(args[1]))
			}
		case "config":
			if len(args) > 1 && securityTarget(args[1]) && value(args, "start=") == "disabled" {
				h.addScore("disable:" + targetKey(args[1]))
			}
		}
	case "net", "net1":
		if len(args) > 1 && args[0] == "stop" && securityTarget(args[1]) {
			h.addScore("stop:" + targetKey(args[1]))
		}
	case "taskkill":
		if hasWord(args, "/f") || hasWord(args, "-f") {
			for _, f := range []string{"/im", "-im"} {
				if t := next(args, f); t != "" && securityTarget(t) {
					h.addScore("kill:" + targetKey(t))
				}
			}
		}
	case "reg":
		if len(args) > 0 && args[0] == "add" {
			v, d := next(args, "/v"), next(args, "/d")
			if defenderValues[strings.Trim(v, `"'`)] && d != "" && !falseValue(d) {
				h.addScore("reg:" + v)
			}
		}
	case "netsh":
		if hasWord(args, "advfirewall") && hasWord(args, "set") && next(args, "state") == "off" ||
			hasWord(args, "firewall") && next(args, "opmode") == "disable" {
			h.addScore("firewall:off")
		}
	case "add-mppreference":
		for _, a := range args {
			if strings.HasPrefix(a, "-exclusion") {
				h.addScore("mp:" + strings.SplitN(a, ":", 2)[0])
			}
		}
	case "set-mppreference":
		for j, a := range args {
			if !strings.HasPrefix(a, "-disable") {
				continue
			}
			name, v, ok := strings.Cut(a, ":")
			if !ok && j+1 < len(args) {
				v = args[j+1]
			}
			if !falseValue(v) {
				h.addScore("mp:" + name)
			}
		}
	case "stop-service":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && securityTarget(a) {
				h.addScore("stop:" + targetKey(a))
			}
		}
	case "set-service":
		if next(args, "-startuptype") == "disabled" {
			for _, a := range args {
				if !strings.HasPrefix(a, "-") && a != "disabled" && securityTarget(a) {
					h.addScore("disable:" + targetKey(a))
				}
			}
		}
	case "new-service":
		if bin := next(args, "-binarypathname"); strings.Contains(bin, ".sys") {
			byovd(h, bin)
		}
	}
}

// byovd records a kernel driver service: outside the system driver
// directories it is a hit at once; inside, the initiator decides.
func byovd(h *hit, bin string) {
	l := driverPath(bin)
	if h.driver != "" && !h.inDrivers {
		return // an outside driver already decided it
	}
	h.critical(catBYOVD)
	h.driver, h.inDrivers = l, inDriverDirs(l)
}

// driverPath is a service binary path, lower case with forward slashes and
// SCM's prefixes expanded (\??\, \SystemRoot\, %SystemRoot%, a path
// relative to the Windows directory).
func driverPath(bin string) string {
	l := winPath(strings.Trim(bin, `"'`))
	for _, p := range []string{"/systemroot/", "%systemroot%/", "%windir%/"} {
		if rest, ok := strings.CutPrefix(l, p); ok {
			return sysRoot + "/" + rest
		}
	}
	if strings.HasPrefix(l, "system32/") {
		return sysRoot + "/" + l
	}
	return l
}

func inDriverDirs(l string) bool {
	return !strings.Contains(l, "/../") && !strings.Contains(l, "/./") &&
		(strings.HasPrefix(l, sysRoot+"/system32/drivers/") || strings.HasPrefix(l, sysRoot+"/system32/driverstore/filerepository/"))
}

// linuxSecurityUnits are security services and daemons on Linux (no
// .service suffix).
var linuxSecurityUnits = map[string]bool{"siem-agent": true, "auditd": true, "falcon-sensor": true,
	"wazuh-agent": true, "osqueryd": true, "mdatp": true, "wdavdaemon": true, "sysmon": true,
	"clamav-daemon": true, "clamd": true, "ossec": true, "elastic-agent": true, "sentinelone": true,
	"sentinel-agent": true, "cbagentd": true, "ds_agent": true, "auditbeat": true}

// moduleDirs are where nobody installs a kernel module from.
var moduleDirs = []string{"/tmp/", "/dev/shm/", "/home/", "/var/tmp/", "/run/user/"}

func moduleFile(a string) bool {
	for _, s := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
		if strings.HasSuffix(a, s) {
			return true
		}
	}
	return false
}

// abbrev reports whether w abbreviates word (btrfs takes any unique prefix).
func abbrev(w, word string, min int) bool {
	return len(w) >= min && strings.HasPrefix(word, w)
}

// classifyLinux matches a Linux exec's command line; cwd resolves a
// relative module path (called only for one).
func classifyLinux(cmdline string, cwd func() string) *hit {
	h := &hit{}
	for _, cmd := range commands(cmdline) {
		for i, w := range cmd {
			linuxCommand(h, toolName(w), cmd[i+1:], cwd)
		}
	}
	return h.result()
}

func linuxCommand(h *hit, tool string, args []string, cwd func() string) {
	operands := func(from int) []string {
		var out []string
		for _, a := range args[min(from, len(args)):] {
			if !strings.HasPrefix(a, "-") {
				out = append(out, a)
			}
		}
		return out
	}
	switch tool {
	case "lvremove":
		for _, a := range operands(0) {
			if strings.Contains(a, "snap") {
				h.critical(catSnapshot)
			}
		}
	case "zfs":
		if len(args) > 0 && args[0] == "destroy" {
			for _, a := range operands(1) {
				if strings.Contains(a, "@") {
					h.critical(catSnapshot)
				}
			}
		}
	case "btrfs":
		if len(args) > 2 && abbrev(args[0], "subvolume", 2) && abbrev(args[1], "delete", 1) {
			for _, a := range operands(2) {
				if strings.Contains(a, "snap") {
					h.critical(catSnapshot)
				}
			}
		}
	case "insmod", "modprobe":
		for _, a := range operands(0) {
			if !moduleFile(a) {
				continue
			}
			if !strings.HasPrefix(a, "/") {
				dir := cwd()
				if dir == "" {
					continue
				}
				a = dir + "/" + a
			}
			a = path.Clean(a)
			for _, d := range moduleDirs {
				if strings.HasPrefix(a, d) {
					h.critical(catModule)
				}
			}
		}
	case "systemctl":
		ops := operands(0)
		if len(ops) < 2 {
			return
		}
		switch ops[0] {
		case "stop", "disable", "mask", "kill":
			for _, u := range ops[1:] {
				if u = strings.TrimSuffix(u, ".service"); linuxSecurityUnits[u] {
					h.addScore(ops[0] + ":" + u)
				}
			}
		}
	case "service":
		if len(args) > 1 && args[1] == "stop" && linuxSecurityUnits[args[0]] {
			h.addScore("stop:" + args[0])
		}
	case "pkill", "killall":
		for _, a := range operands(0) {
			if linuxSecurityUnits[a] {
				h.addScore("kill:" + a)
			}
		}
	case "auditctl":
		if next(args, "-e") == "0" {
			h.addScore("auditctl:off")
		}
	case "setenforce":
		if len(args) > 0 && (args[0] == "0" || args[0] == "permissive") {
			h.addScore("selinux:off")
		}
	}
}
