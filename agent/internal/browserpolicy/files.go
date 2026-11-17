package browserpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// linuxChromium: each Chromium browser's system-wide managed policy folder
// and the paths whose presence means it is installed (distribution
// packages; snap and flatpak builds read their own folders and are not
// covered).
var linuxChromium = []struct {
	name    string
	managed string
	markers []string
}{
	{"chrome", "/etc/opt/chrome/policies/managed", []string{"/opt/google/chrome"}},
	{"chromium", "/etc/chromium/policies/managed", []string{"/usr/lib/chromium", "/usr/bin/chromium"}},
	{"chromium", "/etc/chromium-browser/policies/managed", []string{"/usr/lib/chromium-browser", "/usr/bin/chromium-browser"}},
	{"edge", "/etc/opt/edge/policies/managed", []string{"/opt/microsoft/msedge"}},
	{"brave", "/etc/brave/policies/managed", []string{"/opt/brave.com"}},
}

// Firefox reads one system-wide policies.json.
var (
	linuxFirefoxPolicies = "/etc/firefox/policies/policies.json"
	linuxFirefoxMarkers  = []string{"/usr/lib/firefox", "/usr/lib/firefox-esr", "/opt/firefox"}
)

func firefoxPolicies() []byte {
	b, _ := json.MarshalIndent(map[string]any{"policies": map[string]any{
		"DNSOverHTTPS": map[string]any{"Enabled": false, "Locked": true}}}, "", "  ")
	return append(b, '\n')
}

// FileApplier writes the policies as managed-policy files (Linux). Root
// prefixes every path (tests); StatePath keeps what the agent wrote.
type FileApplier struct {
	Root      string
	StatePath string
}

type fileState struct {
	FirefoxSHA256 string `json:"firefox_sha256,omitempty"` // of the policies.json the agent wrote
}

func (a *FileApplier) path(p string) string { return filepath.Join(a.Root, p) }

func (a *FileApplier) installed(markers []string) bool {
	for _, m := range markers {
		if _, err := os.Stat(a.path(m)); err == nil {
			return true
		}
	}
	return false
}

func (a *FileApplier) load() fileState {
	var st fileState
	if b, err := os.ReadFile(a.StatePath); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (a *FileApplier) save(st fileState) {
	if a.StatePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(a.StatePath), 0o755)
	b, _ := json.Marshal(st)
	_ = os.WriteFile(a.StatePath, b, 0o600)
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// othersKeys are the policies other files in a managed folder set (an
// administrator's): the agent leaves those to them.
func othersKeys(dir string) map[string]bool {
	out := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || e.Name() == FileName || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			for k := range m {
				out[k] = true
			}
		}
	}
	return out
}

func (a *FileApplier) Apply(on bool) []Result {
	st := a.load()
	var res []Result
	for _, b := range linuxChromium {
		dir := a.path(b.managed)
		ours := filepath.Join(dir, FileName)
		if !on {
			if err := os.Remove(ours); err == nil {
				res = append(res, Result{Browser: b.name, Policy: FileName, Action: "removed"})
			} else if !os.IsNotExist(err) {
				res = append(res, Result{Browser: b.name, Policy: FileName, Action: "error", Error: err.Error()})
			}
			continue
		}
		if !a.installed(b.markers) {
			continue
		}
		taken := othersKeys(dir)
		want := map[string]any{}
		var names []string
		for k, v := range chromiumPolicies() {
			names = append(names, k)
			if taken[k] {
				continue
			}
			want[k] = v
		}
		sort.Strings(names)
		var err error
		if len(want) == 0 {
			err = os.Remove(ours)
			if os.IsNotExist(err) {
				err = nil
			}
		} else {
			data, _ := json.MarshalIndent(want, "", "  ")
			err = writeAtomic(ours, append(data, '\n'))
		}
		for _, k := range names {
			switch {
			case taken[k]:
				res = append(res, Result{Browser: b.name, Policy: k, Action: "kept"})
			case err != nil:
				res = append(res, Result{Browser: b.name, Policy: k, Action: "error", Error: err.Error()})
			default:
				res = append(res, Result{Browser: b.name, Policy: k, Action: "set"})
			}
		}
	}

	fx := a.path(linuxFirefoxPolicies)
	cur, readErr := os.ReadFile(fx)
	sum := ""
	if readErr == nil {
		h := sha256.Sum256(cur)
		sum = hex.EncodeToString(h[:])
	}
	mine := sum != "" && sum == st.FirefoxSHA256
	switch {
	case !on:
		if mine {
			if err := os.Remove(fx); err != nil {
				res = append(res, Result{Browser: "firefox", Policy: "DNSOverHTTPS", Action: "error", Error: err.Error()})
			} else {
				res = append(res, Result{Browser: "firefox", Policy: "DNSOverHTTPS", Action: "removed"})
				st.FirefoxSHA256 = ""
			}
		}
	case !a.installed(linuxFirefoxMarkers):
	case mine:
		res = append(res, Result{Browser: "firefox", Policy: "DNSOverHTTPS", Action: "set"})
	case readErr == nil:
		// a policies.json the agent did not write: the administrator's
		res = append(res, Result{Browser: "firefox", Policy: "DNSOverHTTPS", Action: "kept"})
	default:
		data := firefoxPolicies()
		if err := writeAtomic(fx, data); err != nil {
			res = append(res, Result{Browser: "firefox", Policy: "DNSOverHTTPS", Action: "error", Error: err.Error()})
		} else {
			h := sha256.Sum256(data)
			st.FirefoxSHA256 = hex.EncodeToString(h[:])
			res = append(res, Result{Browser: "firefox", Policy: "DNSOverHTTPS", Action: "set"})
		}
	}
	a.save(st)
	return res
}
