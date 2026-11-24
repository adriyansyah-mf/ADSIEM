package usbguard

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakePlatform struct {
	mu        sync.Mutex
	blocked   []string
	unblocked []string
	fail      error
	tries     int
}

func (f *fakePlatform) block(d Device) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.fail != nil {
		return f.fail
	}
	f.blocked = append(f.blocked, d.ID)
	return nil
}

func (f *fakePlatform) unblock(d Device) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unblocked = append(f.unblocked, d.ID)
	return nil
}

type rig struct {
	g     *Guard
	plat  *fakePlatform
	mode  string
	allow []string
	lines []map[string]any
}

func newRig(mode string, allow ...string) *rig {
	r := &rig{plat: &fakePlatform{}, mode: mode, allow: allow}
	r.g = newGuard(Options{
		Mode:  func() string { return r.mode },
		Allow: func() []string { return r.allow },
		Push: func(logType, line string) {
			if logType != LogType {
				panic(logType)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				panic(err)
			}
			r.lines = append(r.lines, m)
		},
	}, r.plat)
	return r
}

func (r *rig) actions() []string {
	var out []string
	for _, l := range r.lines {
		out = append(out, l["action"].(string))
	}
	return out
}

var stick = Device{ID: "/devices/usb1/1-2", VendorID: "0781", ProductID: "5567", Serial: "4C5300012311",
	Vendor: "SanDisk", Product: "Cruzer Blade"}

func TestAllowed(t *testing.T) {
	cases := []struct {
		allow []string
		want  bool
	}{
		{nil, false},
		{[]string{"0781:5567"}, true},                 // the model
		{[]string{"0781:5567:4c5300012311"}, true},    // this unit, any case
		{[]string{"0781:5567:OTHER"}, false},          // another unit
		{[]string{"0781:9999", " 0781:5567 "}, true},  // any entry
		{[]string{"0781"}, false},                     // malformed
		{[]string{"0781:5567:4C5300012311:x"}, false}, // malformed
	}
	for _, c := range cases {
		if got := Allowed(c.allow, stick); got != c.want {
			t.Errorf("Allowed(%v) = %v", c.allow, got)
		}
	}
	noSerial := stick
	noSerial.Serial = ""
	if Allowed([]string{"0781:5567:"}, noSerial) {
		t.Error("an empty serial entry must not match a device without serial")
	}
}

func TestAuditReportsConnectAndRemoveOnce(t *testing.T) {
	r := newRig("")
	r.g.Arrived(stick)
	r.g.Arrived(stick) // the same device seen again (scan + event)
	r.g.Left(stick.ID)
	if got := r.actions(); len(got) != 2 || got[0] != "connected" || got[1] != "removed" {
		t.Fatalf("%v", got)
	}
	l := r.lines[0]
	if l["mode"] != "audit" || l["vendor_id"] != "0781" || l["serial"] != "4C5300012311" || l["allowed"] != false ||
		l["blocked"] != false || l["event"] != "usb_storage" {
		t.Fatalf("%v", l)
	}
	if len(r.plat.blocked) != 0 {
		t.Fatal("audit must not block")
	}
}

func TestBlockCutsOffAllButTheAllowList(t *testing.T) {
	r := newRig("block", "0781:5567:4C5300012311")
	other := Device{ID: "/devices/usb1/1-3", VendorID: "090C", ProductID: "1000"}
	r.g.Arrived(stick)
	r.g.Arrived(other)
	if got := r.actions(); len(got) != 2 || got[0] != "connected" || got[1] != "blocked" {
		t.Fatalf("%v", got)
	}
	if r.lines[0]["allowed"] != true || r.lines[1]["blocked"] != true {
		t.Fatalf("%v", r.lines)
	}
	if len(r.plat.blocked) != 1 || r.plat.blocked[0] != other.ID {
		t.Fatalf("%v", r.plat.blocked)
	}
	// unplugged and plugged back: blocked again, not remembered as done
	r.g.Left(other.ID)
	r.g.Arrived(other)
	if len(r.plat.blocked) != 2 {
		t.Fatalf("a re-plug must be blocked again: %v", r.plat.blocked)
	}
}

func TestPolicyChangesApplyToDevicesPluggedIn(t *testing.T) {
	r := newRig("audit")
	r.g.Arrived(stick)
	r.mode = "block"
	r.g.Reapply()
	if len(r.plat.blocked) != 1 {
		t.Fatalf("switching to block must cut off what is plugged in: %v", r.plat.blocked)
	}
	r.allow = []string{"0781:5567"}
	r.g.Reapply()
	if len(r.plat.unblocked) != 1 {
		t.Fatalf("allowing it must let it back: %v", r.plat.unblocked)
	}
	// the kernel re-enumerates it: reported as connected again
	r.g.Arrived(stick)
	if got := r.actions(); got[len(got)-1] != "connected" {
		t.Fatalf("%v", got)
	}
	// off releases a blocked device too, and reports nothing
	r.allow = nil
	r.mode = "block"
	r.g.Reapply()
	n := len(r.lines)
	r.mode = "off"
	r.g.Reapply()
	if len(r.plat.unblocked) != 2 || len(r.lines) != n {
		t.Fatalf("unblocked %v lines %d->%d", r.plat.unblocked, n, len(r.lines))
	}
}

func TestOffReportsNothing(t *testing.T) {
	r := newRig("off")
	r.g.Arrived(stick)
	r.g.Left(stick.ID)
	if len(r.lines) != 0 || len(r.plat.blocked) != 0 {
		t.Fatalf("%v %v", r.lines, r.plat.blocked)
	}
}

func TestAFailedBlockIsReportedOnce(t *testing.T) {
	r := newRig("block")
	r.plat.fail = errors.New("permission denied")
	r.g.Arrived(stick)
	r.g.Reapply()
	if got := r.actions(); len(got) != 1 || got[0] != "block_failed" || r.lines[0]["error"] != "permission denied" {
		t.Fatalf("%v %v", got, r.lines)
	}
}

// Windows refuses an eject while something holds the drive (Explorer or
// AutoPlay right after plug-in, an antivirus scan): the block must be tried
// again until it takes, not left failed until the stick is re-plugged.
func TestAFailedBlockIsRetriedUntilItTakes(t *testing.T) {
	r := newRig("block")
	now := time.Date(2026, 11, 23, 17, 11, 58, 0, time.UTC)
	r.g.now = func() time.Time { return now }
	r.plat.fail = errors.New("eject vetoed (windows app) by \\Device\\HarddiskVolume3\\Windows\\explorer.exe; retrying")
	r.g.Arrived(stick)
	if got := r.actions(); len(got) != 1 || got[0] != "block_failed" || r.plat.tries != 1 {
		t.Fatalf("first try: %v tries=%d", got, r.plat.tries)
	}
	r.g.RetryFailed() // not due yet
	if r.plat.tries != 1 {
		t.Fatalf("retried before RetryMin: tries=%d", r.plat.tries)
	}
	now = now.Add(RetryMin)
	r.g.RetryFailed() // due, still held: no second report
	if r.plat.tries != 2 || len(r.actions()) != 1 {
		t.Fatalf("second try: %v tries=%d", r.actions(), r.plat.tries)
	}
	now = now.Add(RetryMin) // backed off to 2*RetryMin: not due yet
	r.g.RetryFailed()
	if r.plat.tries != 2 {
		t.Fatalf("no back-off: tries=%d", r.plat.tries)
	}
	now = now.Add(RetryMin)
	r.plat.fail = nil // Explorer let go
	r.g.RetryFailed()
	if got := r.actions(); r.plat.tries != 3 || len(got) != 2 || got[1] != "blocked" {
		t.Fatalf("block that took: %v tries=%d", got, r.plat.tries)
	}
	now = now.Add(RetryMax)
	r.g.RetryFailed()
	if r.plat.tries != 3 || len(r.actions()) != 2 {
		t.Fatalf("retried a blocked device: %v tries=%d", r.actions(), r.plat.tries)
	}
}

func TestRetryBackOffStopsAtRetryMax(t *testing.T) {
	r := newRig("block")
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	r.g.now = func() time.Time { return now }
	r.plat.fail = errors.New("held")
	r.g.Arrived(stick)
	for i := 0; i < 20; i++ {
		now = now.Add(RetryMax)
		r.g.RetryFailed()
	}
	if r.plat.tries != 21 {
		t.Fatalf("a held device must be tried every RetryMax at worst: tries=%d", r.plat.tries)
	}
	if got := r.actions(); len(got) != 1 {
		t.Fatalf("reported more than once: %v", got)
	}
}

func TestNoRetryOnceTheDeviceLeftOrIsAllowedOrTheModeChanged(t *testing.T) {
	r := newRig("block")
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	r.g.now = func() time.Time { return now }
	r.plat.fail = errors.New("held")

	r.g.Arrived(stick)
	r.g.Left(stick.ID)
	now = now.Add(RetryMax)
	r.g.RetryFailed()
	if r.plat.tries != 1 {
		t.Fatalf("retried an unplugged device: tries=%d", r.plat.tries)
	}

	r.g.Arrived(stick) // tries=2, fails
	r.allow = []string{"0781:5567"}
	now = now.Add(RetryMax)
	r.g.RetryFailed()
	if got := r.actions(); r.plat.tries != 2 || got[len(got)-1] != "connected" {
		t.Fatalf("allowed meanwhile: %v tries=%d", got, r.plat.tries)
	}

	r.allow = nil
	r.g.Left(stick.ID)
	r.g.Arrived(stick) // tries=3, fails
	r.mode = "audit"
	now = now.Add(RetryMax)
	r.g.RetryFailed()
	if r.plat.tries != 3 {
		t.Fatalf("retried under audit: tries=%d", r.plat.tries)
	}
}

func TestParseWindowsUSBID(t *testing.T) {
	cases := []struct {
		id, vid, pid, serial string
		ok                   bool
	}{
		{`USB\VID_0781&PID_5567\4C530001231122115172`, "0781", "5567", "4C530001231122115172", true},
		{`usb\vid_090c&pid_1000\6&2a7c1f3&0&2`, "090C", "1000", "", true}, // no serial: Windows made one up
		{`USB\VID_05AC&PID_12A8&MI_00\7&1234&0&0000`, "05AC", "12A8", "", true},
		{`USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA\4C53&0`, "", "", "", false},
		{`USB\ROOT_HUB30\4&1234&0&0`, "", "", "", false},
	}
	for _, c := range cases {
		vid, pid, serial, ok := ParseWindowsUSBID(c.id)
		if vid != c.vid || pid != c.pid || serial != c.serial || ok != c.ok {
			t.Errorf("%s: %q %q %q %v", c.id, vid, pid, serial, ok)
		}
	}
}
