//go:build linux

package usbguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// sysRoot is /sys; tests point it at a fake tree.
var sysRoot = "/sys"

const massStorageClass = "08"

// linuxPlatform blocks with the kernel's USB device authorization: with
// authorized=0 no driver binds, so the disk never appears; 1 lets it
// enumerate again.
type linuxPlatform struct{}

func (linuxPlatform) block(d Device) error   { return writeAuthorized(d.ID, "0") }
func (linuxPlatform) unblock(d Device) error { return writeAuthorized(d.ID, "1") }

func writeAuthorized(devpath, v string) error {
	return os.WriteFile(filepath.Join(sysRoot, devpath, "authorized"), []byte(v), 0o644)
}

// Start watches kernel uevents until ctx ends. The returned guard's
// Reapply runs a policy change.
func Start(ctx context.Context, opts Options) (*Guard, error) {
	g := newGuard(opts, linuxPlatform{})
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		return nil, fmt.Errorf("uevent socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("uevent bind: %w", err)
	}
	// a read wakes every second, so the loop sees ctx end
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	for _, d := range scan() { // what is plugged in already: block mode applies to it too
		g.Arrived(d)
	}
	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 64*1024)
		for ctx.Err() == nil {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
					continue
				}
				slog.Warn("usb uevent read failed", "err", err)
				time.Sleep(time.Second)
				continue
			}
			g.handleUevent(parseUevent(buf[:n]))
		}
	}()
	return g, nil
}

// parseUevent reads a kernel uevent: "add@/devices/...\0ACTION=add\0KEY=VALUE\0...".
func parseUevent(b []byte) map[string]string {
	out := map[string]string{}
	for i, part := range strings.Split(string(b), "\x00") {
		if i == 0 && strings.Contains(part, "@") {
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

func (g *Guard) handleUevent(ev map[string]string) {
	if ev["SUBSYSTEM"] != "usb" {
		return
	}
	switch {
	case ev["ACTION"] == "add" && ev["DEVTYPE"] == "usb_interface" && strings.HasPrefix(ev["INTERFACE"], "8/"):
		// a mass storage interface: its parent is the USB device
		if d, ok := readDevice(filepath.Dir(ev["DEVPATH"])); ok {
			g.Arrived(d)
		}
	case ev["ACTION"] == "remove" && ev["DEVTYPE"] == "usb_device":
		g.Left(ev["DEVPATH"])
	}
}

func attr(devpath, name string) string {
	b, err := os.ReadFile(filepath.Join(sysRoot, devpath, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readDevice: the USB device at devpath (relative to /sys).
func readDevice(devpath string) (Device, bool) {
	vid, pid := attr(devpath, "idVendor"), attr(devpath, "idProduct")
	if vid == "" || pid == "" {
		return Device{}, false
	}
	return Device{ID: devpath, VendorID: strings.ToUpper(vid), ProductID: strings.ToUpper(pid),
		Serial: attr(devpath, "serial"), Vendor: attr(devpath, "manufacturer"), Product: attr(devpath, "product")}, true
}

// scan: USB devices with a mass storage interface now.
func scan() []Device {
	links, _ := filepath.Glob(filepath.Join(sysRoot, "bus", "usb", "devices", "*"))
	var out []Device
	for _, link := range links {
		if strings.Contains(filepath.Base(link), ":") { // an interface, not a device
			continue
		}
		real, err := filepath.EvalSymlinks(link)
		if err != nil {
			continue
		}
		devpath := strings.TrimPrefix(real, filepath.Clean(sysRoot))
		classes, _ := filepath.Glob(filepath.Join(real, "*:*", "bInterfaceClass"))
		storage := false
		for _, c := range classes {
			if b, err := os.ReadFile(c); err == nil && strings.TrimSpace(string(b)) == massStorageClass {
				storage = true
				break
			}
		}
		if !storage {
			continue
		}
		if d, ok := readDevice(devpath); ok {
			out = append(out, d)
		}
	}
	return out
}
