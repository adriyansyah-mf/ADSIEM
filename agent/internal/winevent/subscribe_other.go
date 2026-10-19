//go:build !windows

package winevent

import "context"

// Subscribe is only available on Windows.
func Subscribe(channel string, emit func(line string), stop <-chan struct{}) error {
	return ErrUnsupported
}

// Query is only available on Windows.
func Query(ctx context.Context, channel, xpath string, limit int, fn func(raw []byte) error) error {
	return ErrUnsupported
}
