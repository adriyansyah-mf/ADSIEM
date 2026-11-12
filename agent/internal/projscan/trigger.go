// Package projscan scans a source project when a developer downloads or
// installs one: `git clone`, `npm install`, `pip install -r`. The fake job
// interview / "coding test" attacks (TraderTraitor, the Bybit and Binance
// thefts) ship their payload inside such a project: a package.json lifecycle
// script, a VS Code task that runs when the folder is opened, or an
// obfuscated JS loader. The behavioural ioa_dev_* chains see the payload once
// it runs; this looks at the project before it does, reports a project_scan
// line (an alert on the server) and warns the user on their desktop.
package projscan

import (
	"path"
	"path/filepath"
	"strings"
)

// Trigger is a project to scan and why.
type Trigger struct {
	Dir    string // the project directory (absolute)
	Kind   string // git_clone, npm_install, pip_install
	Origin string // the repository URL for a clone, when known
	Image  string // the program that triggered it
}

// git clone options that take a separate value: skipping them finds the
// positional repository and directory arguments.
var gitValueOpts = map[string]bool{
	"-b": true, "--branch": true, "-o": true, "--origin": true, "-u": true, "--upload-pack": true,
	"--reference": true, "--reference-if-able": true, "--separate-git-dir": true, "--depth": true,
	"--shallow-since": true, "--shallow-exclude": true, "-j": true, "--jobs": true, "--template": true,
	"-c": true, "--config": true, "--filter": true, "--server-option": true, "--bundle-uri": true,
	"--ref-format": true, "--object-format": true,
}

var installVerbs = map[string]bool{"install": true, "i": true, "ci": true, "add": true}

// base is the lower-case program name without directory or Windows
// extension: /usr/bin/git, C:\Program Files\Git\cmd\git.exe and npm.cmd all
// give the bare name.
func base(image string) string {
	b := strings.ToLower(image)
	if i := strings.LastIndexAny(b, `/\`); i >= 0 {
		b = b[i+1:]
	}
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		b = strings.TrimSuffix(b, ext)
	}
	return b
}

// Interesting is a cheap check before FromExec: only these programs are worth
// reading the working directory of.
func Interesting(image string) bool {
	switch name := base(image); name {
	case "git", "gh", "npm", "yarn", "pnpm", "bun":
		return true
	default:
		return strings.HasPrefix(name, "pip")
	}
}

// FromExec recognises a download or install from a process start: image,
// argv (argv[0] included or not) and the process's working directory.
func FromExec(image string, args []string, cwd string) (Trigger, bool) {
	if len(args) > 0 && base(args[0]) == base(image) {
		args = args[1:]
	}
	name := base(image)
	switch {
	case name == "git" && len(args) > 0:
		return gitClone(image, args, cwd)
	case name == "gh" && len(args) >= 3 && args[0] == "repo" && args[1] == "clone":
		repo, dir := args[2], ""
		if len(args) > 3 && !strings.HasPrefix(args[3], "-") {
			dir = args[3]
		}
		return cloneTrigger(image, repo, dir, cwd)
	case name == "npm" || name == "yarn" || name == "pnpm" || name == "bun":
		verb := ""
		if len(args) > 0 {
			verb = args[0]
		}
		// a global install (-g) touches no project
		for _, a := range args {
			if a == "-g" || a == "--global" || a == "--location=global" || (name == "yarn" && a == "global") {
				return Trigger{}, false
			}
		}
		// a bare `yarn` (or `yarn --frozen-lockfile`) installs too; `yarn -v` doesn't
		bareYarn := name == "yarn" && (verb == "" || (strings.HasPrefix(verb, "-") && !yarnInfoFlags[verb]))
		if installVerbs[verb] || bareYarn {
			// npm run by a package's own install script, inside node_modules
			if strings.Contains(strings.ReplaceAll(cwd, `\`, "/"), "/node_modules/") {
				return Trigger{}, false
			}
			return local(image, "npm_install", cwd)
		}
	case strings.HasPrefix(name, "pip"):
		// only installs from the project itself: a plain `pip install pkg`
		// touches site-packages, not a project directory
		if len(args) > 0 && args[0] == "install" {
			for _, a := range args[1:] {
				if a == "-r" || a == "--requirement" || a == "-e" || a == "--editable" || a == "." {
					return local(image, "pip_install", cwd)
				}
			}
		}
	}
	return Trigger{}, false
}

// git's global options that take a separate value (git -C dir clone ...)
var gitGlobalValueOpts = map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true,
	"--namespace": true, "--exec-path": true, "--config-env": true}

var yarnInfoFlags = map[string]bool{"-v": true, "--version": true, "-h": true, "--help": true}

func gitClone(image string, args []string, cwd string) (Trigger, bool) {
	// the subcommand is the first argument that isn't a global option (so
	// `git remote add clone URL` is not a clone); -C changes the directory
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if args[i] == "-C" && i+1 < len(args) {
			if dir, ok := resolve(args[i+1], cwd); ok {
				cwd = dir
			}
		}
		if gitGlobalValueOpts[args[i]] {
			i++
		}
		i++
	}
	if i >= len(args) || args[i] != "clone" {
		return Trigger{}, false
	}
	var positional []string
	for j := i + 1; j < len(args); j++ {
		a := args[j]
		switch {
		case a == "--":
			positional = append(positional, args[j+1:]...)
			j = len(args)
		case strings.HasPrefix(a, "-"):
			if gitValueOpts[a] {
				j++
			}
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		return Trigger{}, false
	}
	dir := ""
	if len(positional) > 1 {
		dir = positional[1]
	}
	return cloneTrigger(image, positional[0], dir, cwd)
}

func cloneTrigger(image, repo, dir, cwd string) (Trigger, bool) {
	if dir == "" {
		dir = repoName(repo)
	}
	if dir == "" {
		return Trigger{}, false
	}
	abs, ok := resolve(dir, cwd)
	if !ok {
		return Trigger{}, false
	}
	return Trigger{Dir: abs, Kind: "git_clone", Origin: repo, Image: image}, true
}

// repoName is the directory git clone creates: the last path part of the URL
// without .git (https://x/a/b.git, git@x:a/b, owner/repo for gh).
func repoName(repo string) string {
	r := strings.TrimRight(repo, `/\`)
	if i := strings.LastIndexAny(r, `/\:`); i >= 0 {
		r = r[i+1:]
	}
	return strings.TrimSuffix(r, ".git")
}

func local(image, kind, cwd string) (Trigger, bool) {
	if cwd == "" {
		return Trigger{}, false
	}
	return Trigger{Dir: cwd, Kind: kind, Image: image}, true
}

func resolve(dir, cwd string) (string, bool) {
	if isAbs(dir) {
		return clean(dir), true
	}
	if cwd == "" {
		return "", false
	}
	return clean(join(cwd, dir)), true
}

// Windows paths are handled whatever OS the agent runs on (tests, and lines
// from a Windows sensor parsed elsewhere).
func windowsPath(p string) bool {
	return strings.Contains(p, `\`) || (len(p) >= 2 && p[1] == ':')
}

func isAbs(p string) bool {
	if windowsPath(p) {
		return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') || strings.HasPrefix(p, `\\`)
	}
	return strings.HasPrefix(p, "/")
}

func join(a, b string) string {
	if windowsPath(a) {
		return strings.TrimRight(a, `\`) + `\` + strings.ReplaceAll(b, "/", `\`)
	}
	return path.Join(a, b)
}

func clean(p string) string {
	if windowsPath(p) {
		return strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`)
	}
	return filepath.Clean(p)
}

// FromFileEvent recognises a download or install from a file creation, for
// Windows, where a process start carries no working directory: git writing a
// new repository's .git\HEAD, or npm writing node_modules\.package-lock.json.
func FromFileEvent(image, action, target string) (Trigger, bool) {
	if action != "create" {
		return Trigger{}, false
	}
	lower := strings.ToLower(strings.ReplaceAll(target, "/", `\`))
	name := base(image)
	switch {
	case name == "git" && strings.HasSuffix(lower, `\.git\head`):
		dir := target[:len(target)-len(`\.git\HEAD`)]
		return Trigger{Dir: clean(dir), Kind: "git_clone", Image: image}, true
	case (name == "node" || name == "npm" || name == "bun") && strings.HasSuffix(lower, `\node_modules\.package-lock.json`):
		dir := target[:len(target)-len(`\node_modules\.package-lock.json`)]
		return Trigger{Dir: clean(dir), Kind: "npm_install", Image: image}, true
	}
	return Trigger{}, false
}
