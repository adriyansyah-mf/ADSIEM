// Package browserpolicy closes the browser-side ways around the web block
// (internal/webblock) with the browsers' own managed policies, when the
// group policy's browser_policy is "on":
//
//   - DNS over HTTPS off: Chrome, Edge, Chromium and Brave (DnsOverHttpsMode
//     "off") and Firefox (DNSOverHTTPS disabled and locked). A browser that
//     resolves names over HTTPS never reads the hosts file the web block
//     writes.
//   - Extensions that ask for the "proxy" permission are blocked in the
//     Chromium browsers (ExtensionSettings, "*": blocked_permissions
//     ["proxy"]): a VPN or proxy extension needs it to route the browser's
//     traffic, so no list of extension ids is needed. Firefox has no such
//     setting; its VPN extensions are still only seen, not blocked.
//
// Windows: values under HKLM\SOFTWARE\Policies (registry). Linux: a file of
// our own (adsiem.json) in each installed Chromium browser's managed policy
// folder, and Firefox's policies.json when there is none.
//
// What an administrator already set is never overwritten: a value the agent
// did not write is kept and reported ("kept"). Turning the policy off
// removes only what the agent wrote, and only while it still holds the
// value the agent wrote.
package browserpolicy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
)

// LogType of the lines Apply emits (decoders/browser_policy.yaml).
const LogType = "browser_policy"

// FileName is the agent's own managed-policy file in a Chromium browser's
// policy folder (Linux).
const FileName = "adsiem.json"

// extensionSettings blocks every extension that asks for the proxy permission.
var extensionSettings = map[string]any{"*": map[string]any{"blocked_permissions": []string{"proxy"}}}

// chromiumPolicies are the Chromium browsers' policies, as the registry
// (strings; ExtensionSettings is JSON) and the managed JSON files take them.
func chromiumPolicies() map[string]any {
	return map[string]any{"DnsOverHttpsMode": "off", "ExtensionSettings": extensionSettings}
}

// Result is the outcome for one browser policy.
type Result struct {
	Browser string // chrome, edge, chromium, brave, firefox
	Policy  string // DnsOverHttpsMode, ExtensionSettings, DNSOverHTTPS
	Action  string // set, kept (an administrator's value), removed, error
	Error   string
}

// Applier puts the policies in place (on) or takes the agent's ones away (off).
type Applier interface {
	Apply(on bool) []Result
}

// Controller applies the group policy's switch and reports changes.
type Controller struct {
	Impl Applier
	Push func(logType, line string)

	mu   sync.Mutex
	last string // the last reported summary, so an unchanged state is not reported again
}

// Apply runs the platform applier and reports the outcome when it changed.
func (c *Controller) Apply(on bool) {
	if c == nil || c.Impl == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	res := c.Impl.Apply(on)
	line := Line(on, res)
	if line == c.last {
		return
	}
	c.last = line
	for _, r := range res {
		if r.Action == "error" {
			slog.Warn("browserpolicy: not applied", "browser", r.Browser, "policy", r.Policy, "err", r.Error)
		}
	}
	if c.Push != nil {
		c.Push(LogType, line)
	}
}

// Line summarises the results for decoders/browser_policy.yaml.
func Line(on bool, res []Result) string {
	mode := "off"
	if on {
		mode = "on"
	}
	by := map[string][]string{}
	var errs []string
	for _, r := range res {
		by[r.Action] = append(by[r.Action], r.Browser+":"+r.Policy)
		if r.Error != "" {
			errs = append(errs, r.Browser+":"+r.Policy+": "+r.Error)
		}
	}
	list := func(a string) string {
		v := by[a]
		sort.Strings(v)
		return strings.Join(v, ",")
	}
	sort.Strings(errs)
	return fmt.Sprintf("event=browser_policy mode=%s set=%s kept=%s removed=%s errors=%s",
		mode, kv(list("set")), kv(list("kept")), kv(list("removed")), kv(strings.Join(errs, "; ")))
}

func kv(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	return `"` + s + `"`
}

// canonical is v as compact JSON (strings as they are), for comparing what
// is in place with what the agent writes.
func canonical(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
