//go:build windows

package webblock

import "syscall"

// Winsock reports a missing IPv6 stack with its own codes.
var platformNoIPv6 = []error{syscall.Errno(10049) /* WSAEADDRNOTAVAIL */, syscall.Errno(10047) /* WSAEAFNOSUPPORT */}
