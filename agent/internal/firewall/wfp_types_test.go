package firewall

import (
	"errors"
	"testing"
	"unsafe"
)

// The WFP structs are handed to fwpuclnt.dll as raw memory: their sizes and
// field offsets must be the C ones on 64-bit Windows (fwpmtypes.h).
func TestWFPStructLayoutMatchesC(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("layout checked for 64-bit builds")
	}
	var f fwpmFilter0
	var c fwpmFilterCondition0
	var s fwpmSublayer0
	var sess fwpmSession0
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof FWPM_FILTER0", unsafe.Sizeof(f), 200},
		{"FWPM_FILTER0.providerKey", unsafe.Offsetof(f.ProviderKey), 40},
		{"FWPM_FILTER0.layerKey", unsafe.Offsetof(f.LayerKey), 64},
		{"FWPM_FILTER0.weight", unsafe.Offsetof(f.Weight), 96},
		{"FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.FilterCondition), 120},
		{"FWPM_FILTER0.action", unsafe.Offsetof(f.Action), 128},
		{"FWPM_FILTER0.providerContext", unsafe.Offsetof(f.ProviderContext), 152},
		{"FWPM_FILTER0.filterId", unsafe.Offsetof(f.FilterID), 176},
		{"sizeof FWPM_FILTER_CONDITION0", unsafe.Sizeof(c), 40},
		{"FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.Value), 24},
		{"sizeof FWPM_SUBLAYER0", unsafe.Sizeof(s), 72},
		{"FWPM_SUBLAYER0.weight", unsafe.Offsetof(s.Weight), 64},
		{"sizeof FWPM_SESSION0", unsafe.Sizeof(sess), 72},
		{"FWPM_SESSION0.sid", unsafe.Offsetof(sess.SID), 48},
		{"sizeof FWP_V4_ADDR_AND_MASK", unsafe.Sizeof(fwpV4AddrAndMask{}), 8},
		{"sizeof FWP_V6_ADDR_AND_MASK", unsafe.Sizeof(fwpV6AddrAndMask{}), 17},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestWFPRulesBlockBothDirectionsInHostOrder(t *testing.T) {
	rules, err := wfpRules([]string{"45.33.32.0/24", "45.33.32.156/32"}, []string{"2606:4700:4700::/48"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 6 {
		t.Fatalf("want 6 filters, got %d", len(rules))
	}
	if rules[0].Layer != layerALEAuthConnectV4 || rules[1].Layer != layerALEAuthRecvAcceptV4 {
		t.Fatal("IPv4 rules must cover connect and receive/accept")
	}
	if m := rules[0].V4; m.Addr != 0x2D212000 || m.Mask != 0xFFFFFF00 {
		t.Fatalf("45.33.32.0/24 = %#x/%#x", m.Addr, m.Mask)
	}
	if m := rules[2].V4; m.Addr != 0x2D21209C || m.Mask != 0xFFFFFFFF {
		t.Fatalf("45.33.32.156/32 = %#x/%#x", m.Addr, m.Mask)
	}
	v6 := rules[4]
	if v6.Layer != layerALEAuthConnectV6 || rules[5].Layer != layerALEAuthRecvAcceptV6 ||
		v6.V6.PrefixLength != 48 || v6.V6.Addr[0] != 0x26 || v6.V6.Addr[1] != 0x06 {
		t.Fatalf("IPv6 rule: %+v", v6.V6)
	}
	if _, err := wfpRules([]string{"nope"}, nil); err == nil {
		t.Fatal("a bad CIDR must fail")
	}
}

type fakeIOC struct {
	err   error
	calls [][]string
}

func (f *fakeIOC) SetIOCs(v4, v6 []string) error {
	f.calls = append(f.calls, append(append([]string{}, v4...), v6...))
	return f.err
}

func TestNetshPrefersWFPAndFallsBackToRules(t *testing.T) {
	win := newFakeWindows("SIEM-IOC-in", "SIEM-IOC-out") // left by an earlier netsh fallback
	wfp := &fakeIOC{}
	b := win.backend()
	b.wfp = wfp
	if err := b.SetIOCs([]string{"45.33.32.156/32"}, nil); err != nil {
		t.Fatal(err)
	}
	if b.IOCVia() != "wfp" || len(wfp.calls) != 1 || win.rules["SIEM-IOC-in"] || win.rules["SIEM-IOC-out"] {
		t.Fatalf("WFP must hold the list and stale netsh rules go: via=%q rules=%v", b.IOCVia(), win.rules)
	}

	wfp.err = errors.New("FwpmFilterAdd0: Access is denied.")
	if err := b.SetIOCs([]string{"45.33.32.156/32"}, nil); err != nil {
		t.Fatal(err)
	}
	if b.IOCVia() != "netsh" || !win.rules["SIEM-IOC-in"] || !win.rules["SIEM-IOC-out"] {
		t.Fatalf("netsh must take over: via=%q rules=%v", b.IOCVia(), win.rules)
	}
	if last := wfp.calls[len(wfp.calls)-1]; len(last) != 0 {
		t.Fatalf("a failed WFP set must be emptied, got %v", last)
	}

	wfp.err = nil
	if err := b.SetIOCs(nil, nil); err != nil {
		t.Fatal(err)
	}
	if b.IOCVia() != "" || win.rules["SIEM-IOC-in"] {
		t.Fatalf("clearing: via=%q rules=%v", b.IOCVia(), win.rules)
	}
}
