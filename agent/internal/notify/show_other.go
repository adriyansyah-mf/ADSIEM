//go:build !windows && !linux

package notify

// platformShow is nil: there is no desktop to notify on unsupported platforms.
var platformShow func(title, message string) error
