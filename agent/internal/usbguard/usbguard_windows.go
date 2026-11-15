//go:build windows

package usbguard

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows: present disks are listed every PollInterval (SetupAPI, no WMI);
// a disk whose ancestor is a USB device is USB storage (USBSTOR and UASP
// alike). Blocking ejects that USB device; a re-plug is ejected again.
var PollInterval = 2 * time.Second

var (
	modcfgmgr32         = windows.NewLazySystemDLL("cfgmgr32.dll")
	procCMGetParent     = modcfgmgr32.NewProc("CM_Get_Parent")
	procCMGetDeviceID   = modcfgmgr32.NewProc("CM_Get_Device_IDW")
	procCMRequestEjectW = modcfgmgr32.NewProc("CM_Request_Device_EjectW")
	diskDriveClass      = windows.GUID{Data1: 0x4d36e967, Data2: 0xe325, Data3: 0x11ce,
		Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
)

const crSuccess = 0

type windowsPlatform struct {
	mu   sync.Mutex
	inst map[string]windows.DEVINST // USB device instance ID -> devnode, from the last poll
}

func (p *windowsPlatform) setInst(m map[string]windows.DEVINST) {
	p.mu.Lock()
	p.inst = m
	p.mu.Unlock()
}

func (p *windowsPlatform) block(d Device) error {
	p.mu.Lock()
	inst, ok := p.inst[d.ID]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("device %s is gone", d.ID)
	}
	var veto uint32
	name := make([]uint16, windows.MAX_PATH)
	r, _, _ := procCMRequestEjectW.Call(uintptr(inst), uintptr(unsafe.Pointer(&veto)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), 0)
	if r != crSuccess {
		return fmt.Errorf("eject failed (CONFIGRET %d)", r)
	}
	if veto != 0 {
		return fmt.Errorf("eject vetoed (type %d) by %s", veto, windows.UTF16ToString(name))
	}
	return nil
}

// unblock: an ejected device comes back when it is plugged in again.
func (p *windowsPlatform) unblock(Device) error { return nil }

func parentOf(inst windows.DEVINST) (windows.DEVINST, bool) {
	var parent windows.DEVINST
	r, _, _ := procCMGetParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(inst), 0)
	return parent, r == crSuccess
}

func deviceID(inst windows.DEVINST) string {
	buf := make([]uint16, 512)
	r, _, _ := procCMGetDeviceID.Call(uintptr(inst), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if r != crSuccess {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// usbAncestor: the USB device a disk hangs off, if any (USBSTOR disk ->
// USB device; UASP: SCSI disk -> UAS controller -> USB device).
func usbAncestor(inst windows.DEVINST) (windows.DEVINST, string, bool) {
	cur := inst
	for i := 0; i < 4; i++ {
		parent, ok := parentOf(cur)
		if !ok {
			return 0, "", false
		}
		id := deviceID(parent)
		if strings.HasPrefix(strings.ToUpper(id), `USB\VID_`) {
			return parent, id, true
		}
		cur = parent
	}
	return 0, "", false
}

// present: USB storage now, by USB device instance ID.
func present() (map[string]Device, map[string]windows.DEVINST, error) {
	set, err := windows.SetupDiGetClassDevsEx(&diskDriveClass, "", 0, windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return nil, nil, err
	}
	defer set.Close()
	devices, insts := map[string]Device{}, map[string]windows.DEVINST{}
	for i := 0; ; i++ {
		data, err := set.EnumDeviceInfo(i)
		if err != nil {
			break // ERROR_NO_MORE_ITEMS
		}
		usbInst, usbID, ok := usbAncestor(data.DevInst)
		if !ok {
			continue
		}
		vid, pid, serial, ok := ParseWindowsUSBID(usbID)
		if !ok {
			continue
		}
		name := ""
		if v, err := set.DeviceRegistryProperty(data, windows.SPDRP_FRIENDLYNAME); err == nil {
			name, _ = v.(string)
		}
		devices[usbID] = Device{ID: usbID, VendorID: vid, ProductID: pid, Serial: serial, Product: name}
		insts[usbID] = usbInst
	}
	return devices, insts, nil
}

// Start polls the present disks until ctx ends.
func Start(ctx context.Context, opts Options) (*Guard, error) {
	p := &windowsPlatform{inst: map[string]windows.DEVINST{}}
	g := newGuard(opts, p)
	if _, _, err := present(); err != nil {
		return nil, fmt.Errorf("list disks: %w", err)
	}
	go func() {
		known := map[string]bool{}
		t := time.NewTicker(PollInterval)
		defer t.Stop()
		for {
			devices, insts, err := present()
			if err != nil {
				slog.Warn("usb storage poll failed", "err", err)
			} else {
				p.setInst(insts)
				for id, d := range devices {
					if !known[id] {
						known[id] = true
						g.Arrived(d)
					}
				}
				for id := range known {
					if _, ok := devices[id]; !ok {
						delete(known, id)
						g.Left(id)
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return g, nil
}
