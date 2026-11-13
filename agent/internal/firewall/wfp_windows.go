//go:build windows

package firewall

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fwpuclnt              = windows.NewLazySystemDLL("fwpuclnt.dll")
	procEngineOpen        = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose       = fwpuclnt.NewProc("FwpmEngineClose0")
	procTransactionBegin  = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procTransactionCommit = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procTransactionAbort  = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procSubLayerAdd       = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFilterAdd         = fwpuclnt.NewProc("FwpmFilterAdd0")
)

// wfpIOC holds the IoC blocklist as WFP filters in a dynamic session: Windows
// deletes them when the session's engine handle closes, so they never outlive
// the agent (no stale block after an uninstall or a crash; the agent applies
// its saved list again when it starts). A change builds the new session first
// and only then closes the old one, so the list is never briefly empty.
type wfpIOC struct {
	mu     sync.Mutex
	engine windows.Handle
}

// newPlatformIOC returns the WFP IoC setter, or nil when fwpuclnt.dll lacks it.
func newPlatformIOC() IOCSetter {
	if procEngineOpen.Find() != nil || procFilterAdd.Find() != nil {
		return nil
	}
	return &wfpIOC{}
}

func (w *wfpIOC) Name() string { return "wfp" }

func (w *wfpIOC) SetIOCs(v4, v6 []string) error {
	rules, err := wfpRules(v4, v6)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var next windows.Handle
	if len(rules) > 0 {
		if next, err = wfpOpenDynamic(); err != nil {
			return err
		}
		if err := wfpInstall(next, rules); err != nil {
			wfpClose(next)
			return err
		}
	}
	if w.engine != 0 {
		wfpClose(w.engine)
	}
	w.engine = next
	return nil
}

func wfpCall(p *windows.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: %w", p.Name, windows.Errno(r))
	}
	return nil
}

func wfpOpenDynamic() (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString("SIEM agent IP IoC blocklist")
	session := &fwpmSession0{DisplayData: fwpmDisplayData0{Name: name}, Flags: fwpmSessionFlagDynamic}
	var h windows.Handle
	err := wfpCall(procEngineOpen, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(session)
	runtime.KeepAlive(name)
	if err != nil {
		return 0, err
	}
	return h, nil
}

func wfpClose(h windows.Handle) {
	_, _, _ = procEngineClose.Call(uintptr(h))
}

// wfpInstall adds a sublayer and one block filter per rule in one transaction.
func wfpInstall(h windows.Handle, rules []wfpRule) error {
	if err := wfpCall(procTransactionBegin, uintptr(h), 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = procTransactionAbort.Call(uintptr(h))
		}
	}()

	key, err := windows.GenerateGUID()
	if err != nil {
		return err
	}
	sublayerKey := wfpGUID(key)
	slName, _ := windows.UTF16PtrFromString("SIEM IP IoC")
	sublayer := &fwpmSublayer0{SubLayerKey: sublayerKey, DisplayData: fwpmDisplayData0{Name: slName},
		Weight: wfpSublayerWeight}
	err = wfpCall(procSubLayerAdd, uintptr(h), uintptr(unsafe.Pointer(sublayer)), 0)
	runtime.KeepAlive(sublayer)
	runtime.KeepAlive(slName)
	if err != nil {
		return err
	}

	for _, r := range rules {
		if err := wfpAddFilter(h, sublayerKey, r); err != nil {
			return fmt.Errorf("block %s: %w", r.CIDR, err)
		}
	}
	if err := wfpCall(procTransactionCommit, uintptr(h)); err != nil {
		return err
	}
	committed = true
	return nil
}

func wfpAddFilter(h windows.Handle, sublayer wfpGUID, r wfpRule) error {
	name, _ := windows.UTF16PtrFromString("SIEM IP IoC block " + r.CIDR)
	cond := &fwpmFilterCondition0{FieldKey: conditionIPRemoteAddress, MatchType: fwpMatchEqual}
	if r.V4 != nil {
		cond.Value = fwpValue0{Type: fwpV4AddrMask, Value: uintptr(unsafe.Pointer(r.V4))}
	} else {
		cond.Value = fwpValue0{Type: fwpV6AddrMask, Value: uintptr(unsafe.Pointer(r.V6))}
	}
	filter := &fwpmFilter0{
		DisplayData:         fwpmDisplayData0{Name: name},
		LayerKey:            r.Layer,
		SubLayerKey:         sublayer,
		Weight:              fwpValue0{Type: fwpEmpty},
		NumFilterConditions: 1,
		FilterCondition:     cond,
		Action:              fwpmAction0{Type: fwpActionBlock},
	}
	var id uint64
	err := wfpCall(procFilterAdd, uintptr(h), uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(cond)
	runtime.KeepAlive(name)
	runtime.KeepAlive(r.V4)
	runtime.KeepAlive(r.V6)
	return err
}
