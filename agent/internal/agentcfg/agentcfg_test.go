package agentcfg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/config"
	"github.com/siem-platform/agent/internal/policy"
)

const localURL = "https://siem.example.com"

var t0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

// clock fakes the time Boot sees; set moves it.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func useClock(t *testing.T) *clock {
	t.Helper()
	c := &clock{t: t0}
	old := now
	now = c.now
	t.Cleanup(func() { now = old })
	return c
}

func localCfg() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{URL: localURL, HeartbeatInterval: 30},
		FIM:    config.FimConfig{Enabled: true},
	}
}

func pol(t *testing.T, version, overlay string) *policy.Policy {
	t.Helper()
	p := &policy.Policy{Version: "p-" + version, ConfigVersion: version}
	if overlay != "" {
		var o config.Overlay
		if err := json.Unmarshal([]byte(overlay), &o); err != nil {
			t.Fatal(err)
		}
		p.Settings.AgentConfig = &o
	}
	return p
}

func okProbe(string) error { return nil }

func TestBootNoPolicyIsLocal(t *testing.T) {
	useClock(t)
	dir := t.TempDir()
	for _, p := range []*policy.Policy{nil, pol(t, "", `{"fim":{"enabled":false}}`)} {
		cfg := localCfg()
		r := Boot(cfg, dir, p)
		if !cfg.FIM.Enabled || cfg.Server.URL != localURL {
			t.Fatalf("overlay applied: %+v", cfg)
		}
		if v, e := r.Status(); v != "" || e != "" {
			t.Fatalf("status %q %q", v, e)
		}
		if r.OverlaySetsURL() {
			t.Fatal("OverlaySetsURL with no overlay")
		}
	}
}

func TestBootAppliesOverlay(t *testing.T) {
	useClock(t)
	dir := t.TempDir()
	cfg := localCfg()
	r := Boot(cfg, dir, pol(t, "v1", `{"fim":{"enabled":false},"server":{"heartbeat_interval":60}}`))
	if cfg.FIM.Enabled || cfg.Server.HeartbeatInterval != 60 {
		t.Fatalf("overlay not applied: %+v", cfg)
	}
	if v, e := r.Status(); v != "v1" || e != "" {
		t.Fatalf("status %q %q", v, e)
	}
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st["version"] != "v1" || len(st["starts"].([]any)) != 1 || st["healthy"] != false {
		t.Fatalf("state %s", b)
	}
}

func TestBootOverlayWarningBecomesError(t *testing.T) {
	useClock(t)
	cfg := localCfg()
	r := Boot(cfg, t.TempDir(), pol(t, "v1", `{"server":{"url":"https://evil.example.net"},"fim":{"enabled":false}}`))
	if cfg.Server.URL != localURL || cfg.FIM.Enabled {
		t.Fatalf("cfg %+v", cfg)
	}
	v, e := r.Status()
	if v != "v1" || !strings.Contains(e, "host must stay") {
		t.Fatalf("status %q %q", v, e)
	}
	if r.OverlaySetsURL() {
		t.Fatal("refused url counted as set")
	}
}

func TestBootRejectsAfterThreeFailedStarts(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"fim":{"enabled":false}}`)
	for i := 0; i < 3; i++ {
		cfg := localCfg()
		Boot(cfg, dir, p)
		if cfg.FIM.Enabled {
			t.Fatalf("start %d: overlay not applied", i)
		}
		c.t = c.t.Add(2 * time.Minute) // starts at 0, 2, 4 minutes
	}
	cfg := localCfg()
	r := Boot(cfg, dir, p)
	if !cfg.FIM.Enabled {
		t.Fatal("4th start applied the crashing overlay")
	}
	v, e := r.Status()
	if v != "" || !strings.Contains(e, "kept failing") || !strings.Contains(e, "config v1 rejected") {
		t.Fatalf("status %q %q", v, e)
	}
	// Stays rejected on later starts, even long after.
	c.t = c.t.Add(time.Hour)
	cfg = localCfg()
	r = Boot(cfg, dir, p)
	if !cfg.FIM.Enabled {
		t.Fatal("rejected version applied later")
	}
	if v, e := r.Status(); v != "" || !strings.Contains(e, "v1") {
		t.Fatalf("status %q %q", v, e)
	}
	// A new version is applied again.
	cfg = localCfg()
	r = Boot(cfg, dir, pol(t, "v2", `{"fim":{"enabled":false}}`))
	if cfg.FIM.Enabled {
		t.Fatal("v2 not applied")
	}
	if v, e := r.Status(); v != "v2" || e != "" {
		t.Fatalf("status %q %q", v, e)
	}
}

func TestBootSlowRestartsAreNotCrashes(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"fim":{"enabled":false}}`)
	for i := 0; i < 6; i++ {
		cfg := localCfg()
		Boot(cfg, dir, p)
		if cfg.FIM.Enabled {
			t.Fatalf("start %d rejected", i)
		}
		c.t = c.t.Add(6 * time.Minute) // never 3 within 10 minutes
	}
}

func TestBootHealthyResetsCrashCount(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"fim":{"enabled":false}}`)
	for i := 0; i < 3; i++ {
		r := Boot(localCfg(), dir, p)
		if i == 2 {
			r.MarkHealthy()
		}
		c.t = c.t.Add(time.Minute)
	}
	for i := 0; i < 4; i++ {
		cfg := localCfg()
		r := Boot(cfg, dir, p)
		if cfg.FIM.Enabled {
			t.Fatalf("start %d after healthy rejected", i)
		}
		if _, e := r.Status(); e != "" {
			t.Fatal(e)
		}
		c.t = c.t.Add(time.Minute)
	}
}

func TestBootNewVersionResetsCrashCount(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		Boot(localCfg(), dir, pol(t, "v1", `{"fim":{"enabled":false}}`))
		c.t = c.t.Add(time.Minute)
	}
	for i := 0; i < 3; i++ {
		cfg := localCfg()
		Boot(cfg, dir, pol(t, "v2", `{"fim":{"enabled":false}}`))
		if cfg.FIM.Enabled {
			t.Fatalf("v2 start %d rejected with v1's starts", i)
		}
		c.t = c.t.Add(time.Minute)
	}
}

func TestBootCorruptStateIsIgnored(t *testing.T) {
	useClock(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := localCfg()
	r := Boot(cfg, dir, pol(t, "v1", `{"fim":{"enabled":false}}`))
	if cfg.FIM.Enabled {
		t.Fatal("overlay not applied")
	}
	if v, _ := r.Status(); v != "v1" {
		t.Fatal(v)
	}
}

func TestBootUnwritableStateDirStillBoots(t *testing.T) {
	useClock(t)
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := localCfg()
	r := Boot(cfg, filepath.Join(f, "sub"), pol(t, "v1", `{"fim":{"enabled":false}}`))
	if cfg.FIM.Enabled {
		t.Fatal("overlay not applied")
	}
	r.MarkHealthy()
	if !r.Want(pol(t, "v2", `{}`), okProbe) {
		t.Fatal("Want false")
	}
}

func TestWantSameVersionNoRestart(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"fim":{"enabled":false}}`))
	if r.Want(pol(t, "v1", `{"fim":{"enabled":false}}`), okProbe) {
		t.Fatal("restart for same version")
	}
	if _, e := r.Status(); e != "" {
		t.Fatal(e)
	}
	if r.Want(nil, okProbe) {
		t.Fatal("restart for nil policy")
	}
}

func TestWantEmptyVersion(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), nil)
	if r.Want(pol(t, "", ``), okProbe) {
		t.Fatal("restart with no overlay running and none wanted")
	}
	r = Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"fim":{"enabled":false}}`))
	if !r.Want(pol(t, "", ``), okProbe) {
		t.Fatal("removing the overlay must restart")
	}
}

func TestWantRemovingURLOverlayDoesNotProbe(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"server":{"url":"https://siem.example.com:8443"}}`))
	probe := func(string) error { return errors.New("down") }
	if !r.Want(pol(t, "", ``), probe) {
		t.Fatal("going back to local config must not be blocked by a probe")
	}
}

func TestWantNewVersionRestartsOnce(t *testing.T) {
	useClock(t)
	dir := t.TempDir()
	r := Boot(localCfg(), dir, pol(t, "v1", `{"fim":{"enabled":false}}`))
	v2 := pol(t, "v2", `{"fim":{"enabled":true}}`)
	if !r.Want(v2, okProbe) {
		t.Fatal("no restart for a new version")
	}
	if _, e := r.Status(); e != "" {
		t.Fatal(e)
	}
	// After the restart the agent still boots v1 (e.g. policy.json was not
	// updated): asking again must not loop.
	r = Boot(localCfg(), dir, pol(t, "v1", `{"fim":{"enabled":false}}`))
	if r.Want(v2, okProbe) {
		t.Fatal("restarted again for the same version")
	}
	if _, e := r.Status(); e != "config v2 still differs after restart" {
		t.Fatalf("err %q", e)
	}
	// A later version restarts again.
	if !r.Want(pol(t, "v3", `{}`), okProbe) {
		t.Fatal("no restart for v3")
	}
}

func TestWantRejectedVersionNoRestart(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"fim":{"enabled":false}}`)
	for i := 0; i < 4; i++ {
		Boot(localCfg(), dir, p)
		c.t = c.t.Add(time.Minute)
	}
	r := Boot(localCfg(), dir, nil)
	if r.Want(p, okProbe) {
		t.Fatal("restart for a rejected version")
	}
}

func TestWantURLProbeFailureRejects(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"fim":{"enabled":false}}`))
	var probed []string
	probe := func(u string) error { probed = append(probed, u); return errors.New("boom") }
	v2 := pol(t, "v2", `{"server":{"url":"https://siem.example.com:8443"}}`)
	if r.Want(v2, probe) {
		t.Fatal("restart despite failed probe")
	}
	if len(probed) != 1 || probed[0] != "https://siem.example.com:8443" {
		t.Fatalf("probed %v", probed)
	}
	if _, e := r.Status(); e != "server.url https://siem.example.com:8443 unreachable: boom" {
		t.Fatalf("err %q", e)
	}
	// Rejected: no second probe, no restart, even once the URL works.
	if r.Want(v2, okProbe) || len(probed) != 1 {
		t.Fatal("rejected version tried again")
	}
}

func TestWantURLProbeSuccessRestarts(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), nil)
	var probed []string
	probe := func(u string) error { probed = append(probed, u); return nil }
	if !r.Want(pol(t, "v2", `{"server":{"url":"https://siem.example.com:8443"}}`), probe) {
		t.Fatal("no restart")
	}
	if len(probed) != 1 {
		t.Fatalf("probed %v", probed)
	}
}

func TestWantSameURLSkipsProbe(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"server":{"url":"https://siem.example.com:8443"}}`))
	probe := func(string) error { t.Fatal("probed an unchanged url"); return nil }
	if !r.Want(pol(t, "v2", `{"server":{"url":"https://siem.example.com:8443"},"fim":{"enabled":false}}`), probe) {
		t.Fatal("no restart")
	}
	// An overlay URL the agent would refuse does not change the URL either.
	r = Boot(localCfg(), t.TempDir(), nil)
	if !r.Want(pol(t, "v3", `{"server":{"url":"https://evil.example.net"}}`), probe) {
		t.Fatal("no restart")
	}
}

func TestCheckContactRevertsAfter10m(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"server":{"url":"https://siem.example.com:8443"}}`)
	cfg := localCfg()
	r := Boot(cfg, dir, p)
	if cfg.Server.URL != "https://siem.example.com:8443" || !r.OverlaySetsURL() {
		t.Fatalf("url %q", cfg.Server.URL)
	}
	r.Now = func() time.Time { return t0.Add(9 * time.Minute) }
	if r.CheckContact(time.Time{}) {
		t.Fatal("reverted before 10m")
	}
	r.Now = func() time.Time { return t0.Add(15 * time.Minute) }
	if r.CheckContact(t0.Add(6 * time.Minute)) {
		t.Fatal("reverted despite a recent contact")
	}
	r.Now = func() time.Time { return t0.Add(11 * time.Minute) }
	if !r.CheckContact(time.Time{}) {
		t.Fatal("no revert after 10m without contact")
	}
	if _, e := r.Status(); !strings.Contains(e, "https://siem.example.com:8443 unreachable") {
		t.Fatalf("err %q", e)
	}
	// The restart boots the local URL and leaves v1 alone.
	c.t = t0.Add(12 * time.Minute)
	cfg = localCfg()
	r = Boot(cfg, dir, p)
	if cfg.Server.URL != localURL || r.OverlaySetsURL() {
		t.Fatalf("url %q", cfg.Server.URL)
	}
	if v, _ := r.Status(); v != "" {
		t.Fatal(v)
	}
	if r.Want(p, okProbe) {
		t.Fatal("restart for the reverted version")
	}
}

func TestCheckContactIgnoresLocalURL(t *testing.T) {
	useClock(t)
	r := Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"fim":{"enabled":false}}`))
	r.Now = func() time.Time { return t0.Add(time.Hour) }
	if r.CheckContact(time.Time{}) {
		t.Fatal("reverted a local url")
	}
	r = Boot(localCfg(), t.TempDir(), nil)
	r.Now = func() time.Time { return t0.Add(time.Hour) }
	if r.CheckContact(time.Time{}) {
		t.Fatal("reverted with no overlay")
	}
	// An overlay URL equal to the local one has nothing to fall back to: a
	// server outage must not drop the whole overlay.
	r = Boot(localCfg(), t.TempDir(), pol(t, "v1", `{"server":{"url":"`+localURL+`"}}`))
	r.Now = func() time.Time { return t0.Add(time.Hour) }
	if r.CheckContact(time.Time{}) {
		t.Fatal("reverted to the same url")
	}
}

// A healthy run without the overlay must not credit the overlay's version:
// v1 crashes twice, the overlay is removed, the local run turns healthy,
// then the same v1 comes back and must still be guarded.
func TestMarkHealthyOnlyCreditsRunningVersion(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"fim":{"enabled":false}}`)
	for i := 0; i < 2; i++ {
		Boot(localCfg(), dir, p)
		c.t = c.t.Add(time.Minute)
	}
	r := Boot(localCfg(), dir, pol(t, "", ``))
	c.t = c.t.Add(10 * time.Minute) // MarkHealthy runs after 10 minutes of uptime
	r.MarkHealthy()
	c.t = c.t.Add(time.Minute) // v1's two old starts are now out of the window
	for i := 0; i < 3; i++ {
		cfg := localCfg()
		Boot(cfg, dir, p)
		if cfg.FIM.Enabled {
			t.Fatalf("start %d rejected too early", i)
		}
		c.t = c.t.Add(time.Minute)
	}
	cfg := localCfg()
	r = Boot(cfg, dir, p)
	if !cfg.FIM.Enabled {
		t.Fatal("crash guard off for v1 after a healthy run without it")
	}
	if _, e := r.Status(); !strings.Contains(e, "kept failing") {
		t.Fatalf("err %q", e)
	}
}

// A healthy run of a rejected version's local fallback must not credit it.
func TestMarkHealthyNoopWhenVersionRejected(t *testing.T) {
	c := useClock(t)
	dir := t.TempDir()
	p := pol(t, "v1", `{"fim":{"enabled":false}}`)
	for i := 0; i < 4; i++ {
		Boot(localCfg(), dir, p)
		c.t = c.t.Add(time.Minute)
	}
	Boot(localCfg(), dir, p).MarkHealthy()
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"healthy":true`) {
		t.Fatalf("rejected version marked healthy: %s", b)
	}
}

func TestWantClearsStillDiffersWhenBackToRunning(t *testing.T) {
	useClock(t)
	dir := t.TempDir()
	v1 := pol(t, "v1", `{"fim":{"enabled":false}}`)
	r := Boot(localCfg(), dir, v1)
	v2 := pol(t, "v2", `{}`)
	r.Want(v2, okProbe)
	r = Boot(localCfg(), dir, v1)
	r.Want(v2, okProbe)
	if _, e := r.Status(); !strings.Contains(e, "still differs") {
		t.Fatalf("err %q", e)
	}
	if r.Want(v1, okProbe) {
		t.Fatal("restart for the running version")
	}
	if _, e := r.Status(); e != "" {
		t.Fatalf("stale err %q", e)
	}
}
