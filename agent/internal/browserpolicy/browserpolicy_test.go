package browserpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeReg struct{ m map[string]string }

func (f *fakeReg) Get(key, name string) (string, bool, error) {
	v, ok := f.m[key+`\`+name]
	return v, ok, nil
}
func (f *fakeReg) SetString(key, name, value string) error { f.m[key+`\`+name] = value; return nil }
func (f *fakeReg) SetDWORD(key, name string, value uint32) error {
	f.m[key+`\`+name] = strconv.FormatUint(uint64(value), 10)
	return nil
}
func (f *fakeReg) Delete(key, name string) error { delete(f.m, key+`\`+name); return nil }

func count(res []Result, action string) int {
	n := 0
	for _, r := range res {
		if r.Action == action {
			n++
		}
	}
	return n
}

const chromeKey = `SOFTWARE\Policies\Google\Chrome`

func TestRegistrySetsKeepsAndRemovesOnlyItsOwn(t *testing.T) {
	reg := &fakeReg{m: map[string]string{chromeKey + `\DnsOverHttpsMode`: "secure"}} // set by GPO
	a := &RegistryApplier{Reg: reg, StatePath: filepath.Join(t.TempDir(), "s.json")}
	res := a.Apply(true)
	if count(res, "kept") != 1 || count(res, "set") != 9 {
		t.Fatalf("results: %+v", res)
	}
	if reg.m[chromeKey+`\DnsOverHttpsMode`] != "secure" {
		t.Fatal("an administrator's value must not be overwritten")
	}
	var ext map[string]map[string][]string
	if err := json.Unmarshal([]byte(reg.m[chromeKey+`\ExtensionSettings`]), &ext); err != nil ||
		ext["*"]["blocked_permissions"][0] != "proxy" {
		t.Fatalf("ExtensionSettings: %q", reg.m[chromeKey+`\ExtensionSettings`])
	}
	if reg.m[`SOFTWARE\Policies\Microsoft\Edge\DnsOverHttpsMode`] != "off" ||
		reg.m[`SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\Enabled`] != "0" ||
		reg.m[`SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\Locked`] != "1" {
		t.Fatalf("values: %v", reg.m)
	}
	// idempotent
	if res := a.Apply(true); count(res, "set") != 9 || count(res, "kept") != 1 {
		t.Fatalf("second apply: %+v", res)
	}
	// someone changes one of ours afterwards: off leaves it to them
	reg.m[`SOFTWARE\Policies\Microsoft\Edge\DnsOverHttpsMode`] = "automatic"
	res = a.Apply(false)
	if count(res, "removed") != 8 {
		t.Fatalf("off: %+v", res)
	}
	if reg.m[chromeKey+`\DnsOverHttpsMode`] != "secure" || reg.m[`SOFTWARE\Policies\Microsoft\Edge\DnsOverHttpsMode`] != "automatic" {
		t.Fatalf("off touched values that are not ours: %v", reg.m)
	}
	if len(reg.m) != 2 {
		t.Fatalf("left over: %v", reg.m)
	}
}

func touch(t *testing.T, root, p string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, nil, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestFilesOnlyInstalledBrowsersAndNeverAnAdministratorsKeys(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "/opt/google/chrome/chrome")
	touch(t, root, "/opt/microsoft/msedge/msedge")
	touch(t, root, "/usr/lib/firefox/firefox")
	// the administrator already manages Edge's DoH
	os.MkdirAll(filepath.Join(root, "/etc/opt/edge/policies/managed"), 0o755)
	os.WriteFile(filepath.Join(root, "/etc/opt/edge/policies/managed/company.json"),
		[]byte(`{"DnsOverHttpsMode":"secure","DnsOverHttpsTemplates":"https://dns.example/q"}`), 0o644)
	a := &FileApplier{Root: root, StatePath: filepath.Join(t.TempDir(), "s.json")}
	res := a.Apply(true)

	var chrome map[string]any
	b, err := os.ReadFile(filepath.Join(root, "/etc/opt/chrome/policies/managed", FileName))
	if err != nil || json.Unmarshal(b, &chrome) != nil || chrome["DnsOverHttpsMode"] != "off" || chrome["ExtensionSettings"] == nil {
		t.Fatalf("chrome file: %s %v", b, err)
	}
	var edge map[string]any
	b, _ = os.ReadFile(filepath.Join(root, "/etc/opt/edge/policies/managed", FileName))
	json.Unmarshal(b, &edge)
	if _, has := edge["DnsOverHttpsMode"]; has || edge["ExtensionSettings"] == nil {
		t.Fatalf("edge: the administrator's DoH is left to them: %s", b)
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/brave/policies/managed", FileName)); !os.IsNotExist(err) {
		t.Fatal("a browser that is not installed gets nothing")
	}
	fx, _ := os.ReadFile(filepath.Join(root, linuxFirefoxPolicies))
	if !strings.Contains(string(fx), `"Locked": true`) {
		t.Fatalf("firefox: %s", fx)
	}
	if count(res, "kept") != 1 || count(res, "error") != 0 {
		t.Fatalf("results: %+v", res)
	}

	res = a.Apply(false)
	for _, p := range []string{"/etc/opt/chrome/policies/managed/" + FileName, "/etc/opt/edge/policies/managed/" + FileName,
		linuxFirefoxPolicies} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Fatalf("off left %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/opt/edge/policies/managed/company.json")); err != nil {
		t.Fatal("off removed the administrator's file")
	}
	if count(res, "removed") != 3 {
		t.Fatalf("off results: %+v", res)
	}
}

func TestFirefoxPoliciesOfAnAdministratorAreKept(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "/usr/lib/firefox/firefox")
	admin := []byte(`{"policies":{"DisableTelemetry":true}}`)
	os.MkdirAll(filepath.Join(root, "/etc/firefox/policies"), 0o755)
	os.WriteFile(filepath.Join(root, linuxFirefoxPolicies), admin, 0o644)
	a := &FileApplier{Root: root, StatePath: filepath.Join(t.TempDir(), "s.json")}
	if res := a.Apply(true); count(res, "kept") != 1 {
		t.Fatalf("results: %+v", res)
	}
	a.Apply(false)
	if b, _ := os.ReadFile(filepath.Join(root, linuxFirefoxPolicies)); string(b) != string(admin) {
		t.Fatalf("an administrator's policies.json changed: %s", b)
	}
}

type fixedApplier struct{ res []Result }

func (f fixedApplier) Apply(bool) []Result { return f.res }

func TestControllerReportsOnlyChanges(t *testing.T) {
	var lines []string
	c := &Controller{Impl: fixedApplier{[]Result{{Browser: "chrome", Policy: "DnsOverHttpsMode", Action: "set"}}},
		Push: func(_, l string) { lines = append(lines, l) }}
	c.Apply(true)
	c.Apply(true)
	if len(lines) != 1 || !strings.Contains(lines[0], `mode=on set="chrome:DnsOverHttpsMode"`) {
		t.Fatalf("lines: %v", lines)
	}
	c.Apply(false)
	if len(lines) != 2 {
		t.Fatalf("a mode change is reported: %v", lines)
	}
}
