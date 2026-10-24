//go:build !windows

package winevent

import "context"

// Subscribe is only available on Windows.
func Subscribe(channel string, emit func(line string), stop <-chan struct{}) error {
	return ErrUnsupported
}

// SubscribeResume is only available on Windows.
func SubscribeResume(ctx context.Context, channel string, resume Resume, emit func(Event) error) error {
	return ErrUnsupported
}

// Baseline is only available on Windows.
func Baseline(ctx context.Context, channel string) (Resume, error) {
	return Resume{}, ErrUnsupported
}

// Query is only available on Windows.
func Query(ctx context.Context, channel, xpath string, limit int, fn func(raw []byte) error) error {
	return ErrUnsupported
}
