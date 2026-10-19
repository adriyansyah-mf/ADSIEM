//go:build !windows

package task

import (
	"errors"

	"github.com/siem-platform/agent/internal/firewall"
)

// Linux uses the firewall engine (nftables); see firewall_native_windows.go.
const nativeFirewall = false

var errNoNative = errors.New("no native firewall path on this platform")

func nativeIsolate(string) error { return errNoNative }

func nativeUnisolate() error { return errNoNative }

func nativeBlock(firewall.Rule) error { return errNoNative }

func nativeUnblock(firewall.Rule) error { return errNoNative }
