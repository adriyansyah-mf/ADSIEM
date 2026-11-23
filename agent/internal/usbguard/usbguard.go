// Package usbguard watches USB mass storage (sticks, external disks, card
// readers) and, under the group policy's usb_storage mode, reports or
// blocks it:
//
//   - off: nothing.
//   - audit: every USB storage device that arrives is reported.
//   - block: a device not on usb_allow is cut off (Linux: the kernel's USB
//     authorization, so no driver binds; Windows: ejected, again on every
//     re-plug) and reported; allowed ones are reported as connected.
//     Windows refuses an eject while a program holds the drive open (Explorer
//     or AutoPlay right after plug-in, an antivirus scan, a copy): the block
//     is then retried on every poll, backing off to RetryMax, until it takes.
//
// Keyboards, mice and other USB classes are never touched: a wrong policy
// must not lock anyone out of the host.
//
// Events are "usb" lines (decoders/usb.yaml, rules/usb_storage_*.yaml).
package usbguard

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// LogType of the lines this package pushes.
const LogType = "usb"

// Device is one USB storage device. ID is the platform's stable handle for
// it (Linux: the sysfs device path; Windows: the USB device instance ID).
type Device struct {
	ID        string
	VendorID  string // 4 hex digits, upper case
	ProductID string
	Serial    string
	Vendor    string
	Product   string
}

// Options wire the guard to the agent.
type Options struct {
	Mode  func() string   // off, audit, block; "" is audit
	Allow func() []string // VID:PID or VID:PID:SERIAL
	Push  func(logType, line string)
}

// platform cuts a device off and lets it back.
type platform interface {
	block(Device) error
	unblock(Device) error
}

// A failed block is tried again RetryMin after the failure, then backing off
// (doubling) to RetryMax between tries, for as long as the device stays.
var (
	RetryMin = 2 * time.Second
	RetryMax = 30 * time.Second
)

type retry struct {
	at  time.Time
	gap time.Duration
}

// Guard decides and reports; the platform watchers feed it.
type Guard struct {
	opts Options
	plat platform
	now  func() time.Time

	mu      sync.Mutex
	present map[string]Device // devices here now
	state   map[string]string // ID -> connected | blocked | block_failed
	retries map[string]retry  // ID -> next try of a failed block
}

func newGuard(opts Options, p platform) *Guard {
	return &Guard{opts: opts, plat: p, now: time.Now, present: map[string]Device{}, state: map[string]string{},
		retries: map[string]retry{}}
}

func (g *Guard) mode() string {
	m := ""
	if g.opts.Mode != nil {
		m = strings.ToLower(strings.TrimSpace(g.opts.Mode()))
	}
	switch m {
	case "off", "block":
		return m
	}
	return "audit"
}

func (g *Guard) allow() []string {
	if g.opts.Allow == nil {
		return nil
	}
	return g.opts.Allow()
}

// Allowed: an entry VID:PID matches every unit of that model, VID:PID:SERIAL
// one unit. Hex is case-insensitive; serials compare exactly but for case.
func Allowed(allow []string, d Device) bool {
	for _, e := range allow {
		parts := strings.Split(strings.TrimSpace(e), ":")
		if len(parts) < 2 || len(parts) > 3 {
			continue
		}
		if !strings.EqualFold(parts[0], d.VendorID) || !strings.EqualFold(parts[1], d.ProductID) {
			continue
		}
		if len(parts) == 2 || (d.Serial != "" && strings.EqualFold(parts[2], d.Serial)) {
			return true
		}
	}
	return false
}

// Arrived: a storage device is here (plugged in, or found by a scan).
func (g *Guard) Arrived(d Device) {
	g.mu.Lock()
	g.present[d.ID] = d
	g.mu.Unlock()
	g.evaluate(d)
}

// Left: the device was unplugged (Windows: also ejected by a block). It is
// forgotten, so a re-plug is judged afresh.
func (g *Guard) Left(id string) {
	g.mu.Lock()
	d, ok := g.present[id]
	last := g.state[id]
	delete(g.present, id)
	delete(g.state, id)
	delete(g.retries, id)
	g.mu.Unlock()
	if ok && last == "connected" && g.mode() != "off" {
		g.report(d, "removed", "")
	}
}

// Reapply re-evaluates every device still plugged in (a blocked one too)
// after a policy change: block what is now forbidden, let back what is now
// allowed.
func (g *Guard) Reapply() {
	g.mu.Lock()
	devices := make([]Device, 0, len(g.present))
	for _, d := range g.present {
		devices = append(devices, d)
	}
	g.mu.Unlock()
	for _, d := range devices {
		g.evaluate(d)
	}
}

func (g *Guard) evaluate(d Device) {
	mode := g.mode()
	if mode == "off" {
		g.mu.Lock()
		last := g.state[d.ID]
		g.mu.Unlock()
		if last == "blocked" {
			g.release(d)
		}
		return
	}
	allowed := Allowed(g.allow(), d)
	want := "connected"
	if mode == "block" && !allowed {
		want = "blocked"
	}
	g.mu.Lock()
	last := g.state[d.ID]
	g.mu.Unlock()
	if last == want {
		return
	}
	if want == "connected" {
		if last == "blocked" {
			g.release(d)
			return // it comes back as a new arrival once the driver binds
		}
		g.setState(d.ID, "connected")
		g.report(d, "connected", "")
		return
	}
	if err := g.plat.block(d); err != nil {
		if last == "block_failed" {
			return
		}
		g.setState(d.ID, "block_failed")
		g.mu.Lock()
		g.retries[d.ID] = retry{at: g.now().Add(RetryMin), gap: RetryMin}
		g.mu.Unlock()
		slog.Warn("usb storage block failed", "device", d.ID, "err", err)
		g.report(d, "block_failed", err.Error())
		return
	}
	g.mu.Lock()
	delete(g.retries, d.ID)
	g.mu.Unlock()
	g.setState(d.ID, "blocked")
	g.report(d, "blocked", "")
}

// RetryFailed tries again the blocks that failed and are due (the platform
// watcher calls it on every poll). A block that takes is reported as blocked;
// one that fails again waits twice as long, up to RetryMax, and is not
// reported again (its block_failed line already went out).
func (g *Guard) RetryFailed() {
	if g.mode() != "block" {
		return
	}
	now := g.now()
	var due []Device
	g.mu.Lock()
	for id, r := range g.retries {
		d, ok := g.present[id]
		if !ok || g.state[id] != "block_failed" {
			delete(g.retries, id)
			continue
		}
		if !now.Before(r.at) {
			due = append(due, d)
		}
	}
	g.mu.Unlock()
	allow := g.allow()
	for _, d := range due {
		if Allowed(allow, d) {
			g.mu.Lock()
			delete(g.retries, d.ID)
			g.mu.Unlock()
			g.evaluate(d) // allowed meanwhile: reported as connected
			continue
		}
		if err := g.plat.block(d); err != nil {
			g.mu.Lock()
			r := g.retries[d.ID]
			r.gap *= 2
			if r.gap > RetryMax {
				r.gap = RetryMax
			}
			if r.gap <= 0 {
				r.gap = RetryMin
			}
			r.at = now.Add(r.gap)
			g.retries[d.ID] = r
			g.mu.Unlock()
			slog.Debug("usb storage block retry failed", "device", d.ID, "err", err)
			continue
		}
		g.mu.Lock()
		delete(g.retries, d.ID)
		g.mu.Unlock()
		g.setState(d.ID, "blocked")
		g.report(d, "blocked", "")
	}
}

func (g *Guard) release(d Device) {
	if err := g.plat.unblock(d); err != nil {
		slog.Warn("usb storage unblock failed", "device", d.ID, "err", err)
		return
	}
	g.mu.Lock()
	delete(g.state, d.ID)
	g.mu.Unlock()
}

func (g *Guard) setState(id, s string) {
	g.mu.Lock()
	g.state[id] = s
	g.mu.Unlock()
}

func (g *Guard) report(d Device, action, errText string) {
	if g.opts.Push == nil {
		return
	}
	rec := map[string]any{
		"event": "usb_storage", "action": action, "mode": g.mode(), "device": d.ID,
		"vendor_id": d.VendorID, "product_id": d.ProductID, "serial": d.Serial,
		"vendor": d.Vendor, "product": d.Product, "allowed": Allowed(g.allow(), d),
		"blocked": action == "blocked", "time": g.now().UTC().Format(time.RFC3339),
	}
	if errText != "" {
		rec["error"] = errText
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	g.opts.Push(LogType, string(line))
}

// ParseWindowsUSBID splits a USB device instance ID,
// USB\VID_0781&PID_5567\4C530001231122115172, into vendor, product and
// serial. A serial with '&' is one Windows made up (the device has none).
func ParseWindowsUSBID(id string) (vid, pid, serial string, ok bool) {
	parts := strings.Split(id, `\`)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "USB") {
		return "", "", "", false
	}
	for _, f := range strings.Split(strings.ToUpper(parts[1]), "&") {
		switch {
		case strings.HasPrefix(f, "VID_"):
			vid = f[4:]
		case strings.HasPrefix(f, "PID_"):
			pid = f[4:]
		}
	}
	if vid == "" || pid == "" {
		return "", "", "", false
	}
	if len(parts) > 2 && !strings.Contains(parts[2], "&") {
		serial = parts[2]
	}
	return vid, pid, serial, true
}
