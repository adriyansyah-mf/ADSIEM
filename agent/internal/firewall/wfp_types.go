package firewall

// Windows Filtering Platform (fwpuclnt.dll) types for the IP IoC blocklist,
// laid out as the C headers (fwptypes.h, fwpmtypes.h) on 64-bit Windows.
// They carry no syscalls, so the layout and the filter building are tested on
// every OS (wfp_types_test.go); wfp_windows.go makes the calls.

import (
	"fmt"
	"net/netip"
)

type wfpGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

type fwpByteBlob struct {
	Size uint32
	Data *byte
}

// fwpValue0 is FWP_VALUE0 / FWP_CONDITION_VALUE0: a type and an 8-byte union.
type fwpValue0 struct {
	Type  uint32
	Value uintptr
}

type fwpmSession0 struct {
	SessionKey           wfpGUID
	DisplayData          fwpmDisplayData0
	Flags                uint32
	TxnWaitTimeoutInMSec uint32
	ProcessID            uint32
	SID                  *byte
	Username             *uint16
	KernelMode           int32
}

type fwpmSublayer0 struct {
	SubLayerKey  wfpGUID
	DisplayData  fwpmDisplayData0
	Flags        uint32
	ProviderKey  *wfpGUID
	ProviderData fwpByteBlob
	Weight       uint16
}

type fwpmFilterCondition0 struct {
	FieldKey  wfpGUID
	MatchType uint32
	Value     fwpValue0
}

type fwpmAction0 struct {
	Type       uint32
	FilterType wfpGUID // union with calloutKey
}

type fwpmFilter0 struct {
	FilterKey           wfpGUID
	DisplayData         fwpmDisplayData0
	Flags               uint32
	ProviderKey         *wfpGUID
	ProviderData        fwpByteBlob
	LayerKey            wfpGUID
	SubLayerKey         wfpGUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition0
	Action              fwpmAction0
	ProviderContext     [2]uint64 // union of rawContext and providerContextKey
	Reserved            *wfpGUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
}

type fwpV4AddrAndMask struct {
	Addr uint32 // host byte order
	Mask uint32
}

type fwpV6AddrAndMask struct {
	Addr         [16]byte
	PrefixLength uint8
}

const (
	fwpEmpty      = 0
	fwpV4AddrMask = 0x100
	fwpV6AddrMask = 0x101

	fwpMatchEqual = 0

	fwpActionBlock = 0x1 | 0x1000 // FWP_ACTION_BLOCK | FWP_ACTION_FLAG_TERMINATING

	fwpmSessionFlagDynamic = 0x1
	rpcCAuthnWinNT         = 10

	wfpSublayerWeight = 0x8000
)

var (
	// FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6: outbound connections (and the first
	// UDP send); FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6: inbound ones.
	layerALEAuthConnectV4    = wfpGUID{0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerALEAuthConnectV6    = wfpGUID{0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerALEAuthRecvAcceptV4 = wfpGUID{0xe1cd9fe7, 0xf4b5, 0x4273, [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerALEAuthRecvAcceptV6 = wfpGUID{0xa3b42c97, 0x9f04, 0x4672, [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}
	// FWPM_CONDITION_IP_REMOTE_ADDRESS
	conditionIPRemoteAddress = wfpGUID{0xb235ae9a, 0x1d64, 0x49b8, [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
)

// wfpRule is one block filter to add: a layer and the remote address condition value.
type wfpRule struct {
	Layer wfpGUID
	V4    *fwpV4AddrAndMask
	V6    *fwpV6AddrAndMask
	CIDR  string
}

// wfpRules turns the IoC CIDRs into block filters: each CIDR is blocked
// outbound (connect) and inbound (receive/accept).
func wfpRules(v4, v6 []string) ([]wfpRule, error) {
	out := make([]wfpRule, 0, 2*(len(v4)+len(v6)))
	for _, c := range append(append([]string{}, v4...), v6...) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("wfp: %q: %w", c, err)
		}
		p = p.Masked()
		if p.Addr().Is4() {
			b := p.Addr().As4()
			m := &fwpV4AddrAndMask{
				Addr: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
				Mask: v4Mask(p.Bits()),
			}
			out = append(out, wfpRule{Layer: layerALEAuthConnectV4, V4: m, CIDR: p.String()},
				wfpRule{Layer: layerALEAuthRecvAcceptV4, V4: m, CIDR: p.String()})
			continue
		}
		m := &fwpV6AddrAndMask{Addr: p.Addr().As16(), PrefixLength: uint8(p.Bits())}
		out = append(out, wfpRule{Layer: layerALEAuthConnectV6, V6: m, CIDR: p.String()},
			wfpRule{Layer: layerALEAuthRecvAcceptV6, V6: m, CIDR: p.String()})
	}
	return out, nil
}

func v4Mask(bits int) uint32 {
	if bits <= 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}
