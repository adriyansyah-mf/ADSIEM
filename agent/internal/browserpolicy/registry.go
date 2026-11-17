package browserpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

// Registry is the part of HKLM the Windows applier uses
// (registry_windows.go; a fake in tests). DWORD values read as decimal.
type Registry interface {
	Get(key, name string) (value string, ok bool, err error)
	SetString(key, name, value string) error
	SetDWORD(key, name string, value uint32) error
	Delete(key, name string) error
}

type regValue struct {
	Browser string `json:"browser"`
	Key     string `json:"key"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	DWORD   bool   `json:"dword,omitempty"`
}

func (v regValue) policy() string {
	if v.Browser == "firefox" {
		return "DNSOverHTTPS." + v.Name
	}
	return v.Name
}

// windowsValues are the values the agent puts under HKLM.
func windowsValues() []regValue {
	pol := chromiumPolicies()
	var out []regValue
	for _, b := range []struct{ name, key string }{
		{"chrome", `SOFTWARE\Policies\Google\Chrome`},
		{"edge", `SOFTWARE\Policies\Microsoft\Edge`},
		{"chromium", `SOFTWARE\Policies\Chromium`},
		{"brave", `SOFTWARE\Policies\BraveSoftware\Brave`},
	} {
		for _, name := range []string{"DnsOverHttpsMode", "ExtensionSettings"} {
			out = append(out, regValue{Browser: b.name, Key: b.key, Name: name, Value: canonical(pol[name])})
		}
	}
	fx := `SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`
	return append(out,
		regValue{Browser: "firefox", Key: fx, Name: "Enabled", Value: "0", DWORD: true},
		regValue{Browser: "firefox", Key: fx, Name: "Locked", Value: "1", DWORD: true})
}

// RegistryApplier writes the policies under HKLM (Windows). StatePath keeps
// the values the agent wrote, so off removes only those.
type RegistryApplier struct {
	Reg       Registry
	StatePath string
}

type regState struct {
	Written []regValue `json:"written"`
}

func (a *RegistryApplier) load() regState {
	var st regState
	if b, err := os.ReadFile(a.StatePath); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (a *RegistryApplier) save(st regState) {
	if a.StatePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(a.StatePath), 0o755)
	b, _ := json.Marshal(st)
	_ = os.WriteFile(a.StatePath, b, 0o600)
}

func (a *RegistryApplier) Apply(on bool) []Result {
	st := a.load()
	ours := map[string]regValue{}
	for _, v := range st.Written {
		ours[v.Key+`\`+v.Name] = v
	}
	var res []Result
	var next regState
	if !on {
		for _, v := range st.Written {
			cur, ok, err := a.Reg.Get(v.Key, v.Name)
			switch {
			case err != nil:
				res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "error", Error: err.Error()})
				next.Written = append(next.Written, v) // try again next time
			case ok && cur == v.Value:
				if err := a.Reg.Delete(v.Key, v.Name); err != nil {
					res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "error", Error: err.Error()})
					next.Written = append(next.Written, v)
				} else {
					res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "removed"})
				}
			}
			// changed by someone else, or gone: theirs now, left alone
		}
		a.save(next)
		return res
	}
	for _, v := range windowsValues() {
		id := v.Key + `\` + v.Name
		cur, ok, err := a.Reg.Get(v.Key, v.Name)
		_, mine := ours[id]
		switch {
		case err != nil:
			res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "error", Error: err.Error()})
		case ok && cur == v.Value && mine:
			res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "set"})
			next.Written = append(next.Written, v)
		case ok:
			// an administrator's value (or the same value set by them): kept, never ours to remove
			res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "kept"})
		default:
			var werr error
			if v.DWORD {
				n, _ := strconv.ParseUint(v.Value, 10, 32)
				werr = a.Reg.SetDWORD(v.Key, v.Name, uint32(n))
			} else {
				werr = a.Reg.SetString(v.Key, v.Name, v.Value)
			}
			if werr != nil {
				res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "error", Error: werr.Error()})
				continue
			}
			res = append(res, Result{Browser: v.Browser, Policy: v.policy(), Action: "set"})
			next.Written = append(next.Written, v)
		}
	}
	a.save(next)
	return res
}
