//go:build !linux && !windows

package usbguard

import (
	"context"
	"errors"
)

// Start: USB storage control exists on Linux and Windows only.
func Start(context.Context, Options) (*Guard, error) {
	return nil, errors.New("usb storage control is not supported on this platform")
}
