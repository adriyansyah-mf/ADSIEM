//go:build !windows

package notify

// platformShow is nil: there is no desktop to notify (Linux hosts are
// mostly servers; a tray app would do this per user).
var platformShow func(title, message string) error
