//go:build linux

package usbguard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeSysfs builds /sys/devices/.../1-2 (a stick: mass storage interface)
// and 1-3 (a keyboard), with /sys/bus/usb/devices links, under a temp dir.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dev := func(name, vid, pid, serial, class string) {
		dir := filepath.Join(root, "devices", "pci0000:00", "0000:00:14.0", "usb1", name)
		for file, v := range map[string]string{"idVendor": vid, "idProduct": pid, "serial": serial,
			"manufacturer": "Maker", "product": "Thing " + name, "authorized": "1"} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, file), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		iface := filepath.Join(dir, name+":1.0")
		if err := os.MkdirAll(iface, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(iface, "bInterfaceClass"), []byte(class+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		links := filepath.Join(root, "bus", "usb", "devices")
		if err := os.MkdirAll(links, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir, filepath.Join(links, name)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(iface, filepath.Join(links, name+":1.0")); err != nil {
			t.Fatal(err)
		}
	}
	dev("1-2", "0781", "5567", "4C5300012311", "08")
	dev("1-3", "046d", "c31c", "", "03")
	old := sysRoot
	sysRoot = root
	t.Cleanup(func() { sysRoot = old })
	return root
}

const stickPath = "/devices/pci0000:00/0000:00:14.0/usb1/1-2"

func TestScanFindsStorageOnly(t *testing.T) {
	fakeSysfs(t)
	got := scan()
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	d := got[0]
	if d.ID != stickPath || d.VendorID != "0781" || d.ProductID != "5567" || d.Serial != "4C5300012311" ||
		d.Product != "Thing 1-2" {
		t.Fatalf("%+v", d)
	}
}

func TestUeventsDriveTheGuardAndBlockWritesAuthorized(t *testing.T) {
	root := fakeSysfs(t)
	r := newRig("block")
	r.g.plat = linuxPlatform{}
	msg := "add@" + stickPath + "/1-2:1.0\x00ACTION=add\x00DEVPATH=" + stickPath + "/1-2:1.0\x00SUBSYSTEM=usb\x00" +
		"DEVTYPE=usb_interface\x00INTERFACE=8/6/80\x00SEQNUM=4242\x00"
	ev := parseUevent([]byte(msg))
	if ev["INTERFACE"] != "8/6/80" || ev["DEVPATH"] != stickPath+"/1-2:1.0" {
		t.Fatalf("%v", ev)
	}
	r.g.handleUevent(ev)
	b, _ := os.ReadFile(filepath.Join(root, stickPath, "authorized"))
	if string(b) != "0" {
		t.Fatalf("authorized = %q", b)
	}
	if got := r.actions(); len(got) != 1 || got[0] != "blocked" || r.lines[0]["device"] != stickPath {
		t.Fatalf("%v", r.lines)
	}
	// a keyboard interface is never looked at
	r.g.handleUevent(map[string]string{"SUBSYSTEM": "usb", "ACTION": "add", "DEVTYPE": "usb_interface",
		"INTERFACE": "3/1/1", "DEVPATH": "/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0"})
	// allowed now: authorized back to 1
	r.allow = []string{"0781:5567"}
	r.g.Reapply()
	b, _ = os.ReadFile(filepath.Join(root, stickPath, "authorized"))
	if string(b) != "1" {
		t.Fatalf("authorized = %q", b)
	}
	// unplugged
	r.g.handleUevent(map[string]string{"SUBSYSTEM": "usb", "ACTION": "remove", "DEVTYPE": "usb_device", "DEVPATH": stickPath})
	if len(r.g.present) != 0 || len(r.g.state) != 0 {
		t.Fatalf("%v %v", r.g.present, r.g.state)
	}
}

// The real uevent socket opens without root (kernel uevents are multicast to
// group 1), and a stick already plugged in is judged at start.
func TestStartOpensTheUeventSocketAndScans(t *testing.T) {
	fakeSysfs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var lines []string
	g, err := Start(ctx, Options{Mode: func() string { return "audit" }, Push: func(_, line string) {
		mu.Lock()
		lines = append(lines, line)
		mu.Unlock()
	}})
	if err != nil {
		t.Skipf("no uevent socket here: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if g == nil || len(lines) != 1 || !strings.Contains(lines[0], `"action":"connected"`) {
		t.Fatalf("%v", lines)
	}
}
