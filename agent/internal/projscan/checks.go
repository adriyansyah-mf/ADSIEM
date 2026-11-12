package projscan

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Finding is one suspicious thing in a project.
type Finding struct {
	Severity string // high or medium
	Check    string // npm_lifecycle, vscode_autorun, js_loader, python_setup
	File     string // relative to the project
	Detail   string
}

// Tokens are matched on lower-cased text, as whole words: "irm" must not
// match "confirm", "| sh" not "| shx".
var (
	// high: fetches something and runs it, or decodes and runs it
	fetchTool = regexp.MustCompile(`(^|[^\w.-])(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|certutil|bitsadmin)([^\w-]|$)`)
	runTool   = regexp.MustCompile(`\|\s*(sh|bash|zsh|cmd|powershell|pwsh|iex|node|python3?)([^\w-]|$)|(^|[^\w-])(iex|invoke-expression|mshta|rundll32|regsvr32)([^\w-]|$)|-encodedcommand|\bbase64\b|atob\(|\beval\(|(^|[^\w-])(powershell|pwsh)([^\w-]|$)`)
	// medium: a URL alone (an `echo` of a funding link is common), or inline code
	// (core-js runs `node -e "try{require('./postinstall')}catch(e){}"`)
	urlToken    = regexp.MustCompile(`\b(https?|ftp)://`)
	inlineToken = regexp.MustCompile(`\bnode\s+(-e|--eval|-p)\b|child_process|\bpython3?\s+-c\b`)

	lifecycleScripts = []string{"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
		"prepublish"}
)

// risk rates a command: high when it fetches or decodes and runs something,
// medium for a URL or inline code; what it matched, for the finding.
func risk(cmd string) (string, string) {
	if m := fetchTool.FindString(cmd); m != "" {
		return "high", strings.TrimSpace(strings.Trim(m, "|;&()'\" "))
	}
	if m := runTool.FindString(cmd); m != "" {
		return "high", strings.TrimSpace(strings.Trim(m, "|;&()'\" "))
	}
	if m := urlToken.FindString(cmd); m != "" {
		return "medium", "a URL"
	}
	if m := inlineToken.FindString(cmd); m != "" {
		return "medium", m
	}
	return "", ""
}

// hiddenPath: a path part starting with a dot that isn't . or .. — loaders
// hide in .n2/, .vscode/, .config/ ("node .vscode/settings.js"); not
// node_modules/.bin, where every package's commands live.
var hiddenPath = regexp.MustCompile(`(^|[\s"'/\\])\.[a-z0-9_][\w.-]*[/\\]`)
var binPath = regexp.MustCompile(`node_modules[/\\]\.bin[/\\]`)

// outsidePath: a program started from outside the project: an absolute, home
// or parent path after a runner ("node ../../x.js"); `cd ..` alone is not.
var outsidePath = regexp.MustCompile(`\b(node|python3?|sh|bash|bun|deno)\s+(~[/\\]|\.\.[/\\]|/(tmp|var|etc|home|users)/|[a-z]:\\)`)

// CheckPackageJSON flags lifecycle scripts (run by `npm install` without
// asking) that download, decode or run inline code, or start something
// hidden or outside the project.
func CheckPackageJSON(rel string, data []byte) []Finding {
	var pkg struct {
		Scripts map[string]any `json:"scripts"`
	}
	if json.Unmarshal(stripBOM(data), &pkg) != nil {
		return nil
	}
	var out []Finding
	for _, name := range lifecycleScripts {
		raw, ok := pkg.Scripts[name].(string)
		if !ok || raw == "" {
			continue
		}
		cmd := strings.ToLower(raw)
		sev, what := risk(cmd)
		switch {
		case sev != "":
			out = append(out, Finding{sev, "npm_lifecycle", rel,
				`"` + name + `" script runs ` + what + ": " + excerpt(raw)})
		case hiddenPath.MatchString(binPath.ReplaceAllString(cmd, "")) || outsidePath.MatchString(cmd):
			out = append(out, Finding{"medium", "npm_lifecycle", rel,
				`"` + name + `" script starts a hidden or out-of-project file: ` + excerpt(raw)})
		}
	}
	return out
}

// CheckVSCodeTasks flags tasks that VS Code runs as soon as the folder is
// opened (runOptions.runOn = folderOpen): in a project someone sent you,
// opening it should never run anything. Hidden output or a download makes it
// high.
func CheckVSCodeTasks(rel string, data []byte) []Finding {
	var file struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if json.Unmarshal(stripJSONC(stripBOM(data)), &file) != nil {
		return nil
	}
	var out []Finding
	for _, task := range file.Tasks {
		run, _ := task["runOptions"].(map[string]any)
		if on, _ := run["runOn"].(string); on != "folderOpen" {
			continue
		}
		cmd := strings.ToLower(taskCommand(task))
		pres, _ := task["presentation"].(map[string]any)
		reveal, _ := pres["reveal"].(string)
		hidden := reveal == "never" || reveal == "silent" || pres["echo"] == false || pres["close"] == true
		sev := "medium"
		why := "runs when the folder is opened"
		if r, what := risk(cmd); r == "high" {
			sev, why = "high", why+" and runs "+what
		} else if hidden {
			sev, why = "high", why+" with its output hidden"
		} else if r == "medium" {
			why += " and runs " + what
		}
		label, _ := task["label"].(string)
		out = append(out, Finding{sev, "vscode_autorun", rel,
			"task " + `"` + label + `" ` + why + ": " + excerpt(taskCommand(task))})
	}
	return out
}

// taskCommand is the command and args of a task, including the per-OS variants.
func taskCommand(task map[string]any) string {
	var parts []string
	add := func(t map[string]any) {
		if c, ok := t["command"].(string); ok {
			parts = append(parts, c)
		}
		if args, ok := t["args"].([]any); ok {
			for _, a := range args {
				if s, ok := a.(string); ok {
					parts = append(parts, s)
				}
			}
		}
	}
	add(task)
	for _, osKey := range []string{"windows", "linux", "osx"} {
		if t, ok := task[osKey].(map[string]any); ok {
			add(t)
		}
	}
	return strings.Join(parts, " ")
}

var (
	hexIdent   = regexp.MustCompile(`_0x[0-9a-f]{4,6}`)
	decodeExec = regexp.MustCompile(`(eval|function)\s*\(\s*(atob|buffer\.from|unescape|decodeuricomponent)\s*\(`)
	// not a bare exec(: RegExp.prototype.exec is in almost every JS file
	jsExec    = regexp.MustCompile(`child_process|\bexecsync\s*\(|\bexecfile(sync)?\s*\(|\bspawn(sync)?\s*\(`)
	jsNetwork = regexp.MustCompile(`require\(\s*['"](https?|net|dgram|tls|axios|request|node-fetch|socket\.io-client)['"]|\bfetch\s*\(|new\s+websocket|xmlhttprequest`)
	jsSecrets = regexp.MustCompile(`homedir\(\)|\.ssh|login data|local state|\bwallet|keychain|\.config/solana|exodus|metamask|nkbihfbeogaeaoehlefnkodbefgpgknn|\.aws/credentials|\.npmrc`)
)

// CheckJS flags a JS file that is obfuscated (javascript-obfuscator's _0x
// names, or code decoded and evaluated at run time) and also runs programs or
// talks to the network, or that runs programs, talks to the network and goes
// after credentials or wallets: the shape of the BeaverTail / InvisibleFerret
// loaders. Minified bundles alone don't count.
func CheckJS(rel string, data []byte) []Finding {
	text := strings.ToLower(string(data))
	obfuscated := len(hexIdent.FindAllStringIndex(text, 40)) >= 20 || decodeExec.MatchString(text)
	execs, network, secrets := jsExec.MatchString(text), jsNetwork.MatchString(text), jsSecrets.MatchString(text)
	switch {
	case obfuscated && (execs || network):
		return []Finding{{"high", "js_loader", rel, "obfuscated code that " + capabilities(execs, network, secrets)}}
	case execs && network && secrets:
		return []Finding{{"high", "js_loader", rel, "code that " + capabilities(execs, network, secrets)}}
	case obfuscated:
		return []Finding{{"medium", "js_loader", rel, "obfuscated code"}}
	}
	return nil
}

func capabilities(execs, network, secrets bool) string {
	var c []string
	if execs {
		c = append(c, "runs programs")
	}
	if network {
		c = append(c, "uses the network")
	}
	if secrets {
		c = append(c, "reads credentials or wallets")
	}
	return strings.Join(c, ", ")
}

var (
	pyDecodeExec = regexp.MustCompile(`exec\s*\(\s*(base64|zlib|marshal|codecs|bytes\.fromhex|__import__)`)
	// network at install time; subprocess alone is every build_ext
	pyRisky = regexp.MustCompile(`urllib|requests\.(get|post)|socket\.|urlopen|http\.client`)
)

// CheckPythonSetup flags a setup.py that runs code when installed: a custom
// install command doing network or process work, or a decoded payload.
func CheckPythonSetup(rel string, data []byte) []Finding {
	text := strings.ToLower(string(data))
	switch {
	case pyDecodeExec.MatchString(text):
		return []Finding{{"high", "python_setup", rel, "runs decoded code at install time"}}
	case strings.Contains(text, "cmdclass") && pyRisky.MatchString(text):
		return []Finding{{"high", "python_setup", rel, "custom install command that " + pyRisky.FindString(text)}}
	}
	return nil
}

// stripJSONC removes // and /* */ comments and trailing commas outside
// strings: tasks.json is JSON with comments.
func stripJSONC(data []byte) []byte {
	var out []byte
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			if next := nextSignificant(data, i+1); next == '}' || next == ']' {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// nextSignificant is the next byte that isn't whitespace or inside a comment.
func nextSignificant(data []byte, i int) byte {
	for i < len(data) {
		switch {
		case strings.ContainsRune(" \t\r\n", rune(data[i])):
			i++
		case data[i] == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case data[i] == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i += 2
		default:
			return data[i]
		}
	}
	return 0
}

// stripBOM: npm and VS Code read files with a UTF-8 byte order mark, so must we.
func stripBOM(data []byte) []byte {
	return []byte(strings.TrimPrefix(string(data), "\ufeff"))
}

func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}
