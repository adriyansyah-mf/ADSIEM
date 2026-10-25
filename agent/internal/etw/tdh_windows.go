//go:build windows

package etw

import (
	"fmt"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// decode describes rec with TDH (manifest, TraceLogging and the kernel's MOF
// classes) and formats each top-level property as TDH would display it, so
// no event layout is hard-coded. It stops at the first struct or array
// property (Truncated): the fields this package needs come before any.
func decode(rec *eventRecord) (*Event, error) {
	h := rec.EventHeader
	ev := &Event{
		Provider: h.ProviderID.String(), ID: h.EventDescriptor.ID, Version: h.EventDescriptor.Version,
		Opcode: h.EventDescriptor.Opcode, Task: h.EventDescriptor.Task, PID: h.ProcessID, TID: h.ThreadID,
		Time: time.Unix(0, (h.TimeStamp-116444736000000000)*100).UTC(),
	}
	info, err := eventInformation(rec)
	if err != nil {
		return ev, err
	}
	base := unsafe.Pointer(&info[0])
	tei := (*traceEventInfo)(base)
	ev.ProviderName = utf16At(base, tei.ProviderNameOffset)
	props := unsafe.Slice((*eventPropertyInfo)(unsafe.Add(base, unsafe.Sizeof(traceEventInfo{}))), tei.PropertyCount)

	pointerSize := uint32(8)
	if h.Flags&eventHeaderFlag32BitHeader != 0 {
		pointerSize = 4
	}
	data, remaining := rec.UserData, uint32(rec.UserDataLength)
	numbers := map[int]uint64{} // integer properties, for lengths and counts that refer to them
	for i := 0; i < int(tei.TopLevelPropertyCount) && i < len(props); i++ {
		p := props[i]
		if p.Flags&propertyStruct != 0 {
			ev.Truncated = true
			break
		}
		count := uint64(p.Count)
		if p.Flags&propertyParamCount != 0 {
			count = numbers[int(p.Count)]
		}
		if count != 1 {
			ev.Truncated = true // arrays are not needed: stop here
			break
		}
		length := uint64(p.Length)
		if p.Flags&propertyParamLength != 0 {
			length = numbers[int(p.Length)]
		}
		value, consumed, err := formatProperty(base, pointerSize, p.InType, p.OutType, uint16(length), remaining, data)
		if err != nil {
			ev.Truncated = true
			return ev, err
		}
		name := utf16At(base, p.NameOffset)
		ev.Props = append(ev.Props, Property{Name: name, Value: value})
		if isInteger(p.InType) {
			if n, err := strconv.ParseUint(value, 0, 64); err == nil {
				numbers[i] = n
			}
		}
		data += uintptr(consumed)
		if uint32(consumed) > remaining {
			break
		}
		remaining -= uint32(consumed)
	}
	return ev, nil
}

func eventInformation(rec *eventRecord) ([]uint64, error) {
	var size uint32
	r, _, _ := procTdhGetEventInformation.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 0, uintptr(unsafe.Pointer(&size)))
	if syscall.Errno(r) != errorInsufficientBuffer {
		return nil, fmt.Errorf("etw: TdhGetEventInformation: %w", syscall.Errno(r))
	}
	buf := make([]uint64, (size+7)/8)
	r, _, _ = procTdhGetEventInformation.Call(uintptr(unsafe.Pointer(rec)), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return nil, fmt.Errorf("etw: TdhGetEventInformation: %w", syscall.Errno(r))
	}
	return buf, nil
}

func formatProperty(info unsafe.Pointer, pointerSize uint32, inType, outType, length uint16, remaining uint32, data uintptr) (string, uint16, error) {
	if remaining > 0xffff {
		remaining = 0xffff
	}
	buf := make([]uint16, 128)
	for {
		size := uint32(len(buf) * 2)
		var consumed uint16
		r, _, _ := procTdhFormatProperty.Call(uintptr(info), 0, uintptr(pointerSize), uintptr(inType), uintptr(outType),
			uintptr(length), uintptr(remaining), data, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&consumed)))
		switch syscall.Errno(r) {
		case 0:
			return windows.UTF16ToString(buf), consumed, nil
		case errorInsufficientBuffer:
			buf = make([]uint16, size/2+1)
		default:
			return "", 0, fmt.Errorf("etw: TdhFormatProperty: %w", syscall.Errno(r))
		}
	}
}

func utf16At(base unsafe.Pointer, offset uint32) string {
	if offset == 0 {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Add(base, offset)))
}

// isInteger: TDH_INTYPE_INT8 .. UINT64, HEXINT32, HEXINT64.
func isInteger(t uint16) bool { return (t >= 3 && t <= 10) || t == 20 || t == 21 }
