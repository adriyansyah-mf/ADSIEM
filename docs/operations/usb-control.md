# USB storage control

Policies → a group → **USB storage**. The agent (`agent/internal/usbguard`)
watches USB mass storage: sticks, external disks and USB card readers.

| Mode | What happens |
|---|---|
| `audit` (default) | Every device plugged in is reported. Devices not on the allow list raise **USB Storage Device Connected** (low). |
| `block` | Devices not on the allow list are cut off and raise **USB Storage Device Blocked** (medium). Allowed devices work and are reported. If a block fails, **USB Storage Device Not Blocked** (high) is raised with the reason. |
| `off` | Nothing is watched; anything blocked before is let back. |

Keyboards, mice, network adapters and other USB classes are never touched, so
a wrong policy cannot lock anyone out of a host. Phones in MTP mode are not
mass storage and are not covered.

## Allow list

Add one entry per line:

- `VID:PID` allows every unit of a model.
- `VID:PID:SERIAL` allows one unit.

To find the values:

- **Linux:** `lsusb` (`ID 0781:5567`) or `udevadm info /dev/sdb | grep -E 'ID_(VENDOR|MODEL)_ID|ID_SERIAL_SHORT'`.
- **Windows:** Device Manager → the USB device → Details → Hardware Ids
  (`USB\VID_0781&PID_5567`) and Device instance path (the serial is the last
  part).

Every report carries the device's vendor ID, product ID and serial (the
`device.*` fields), so the easiest way is to plug the device in once in
`audit` and copy the values from the alert.

## How blocking works

- **Linux:** the agent writes `0` to the device's
  `/sys/bus/usb/devices/<port>/authorized`. No driver binds, so no `/dev/sd*`
  ever appears. Allowing the device later, or switching to `off`, writes `1`
  and the disk appears. A device blocked before an agent restart stays cut off
  until it is re-plugged.
- **Windows:** the agent lists disks every 2 seconds. A disk whose parent is
  a USB device is ejected (`CM_Request_Device_EjectW`), and ejected again on
  every re-plug. Windows refuses the eject while files on the device are open;
  the result is the high alert above.
- Internal USB card readers in laptops are mass storage too. Allow their
  `VID:PID` before switching a laptop group to `block`.
