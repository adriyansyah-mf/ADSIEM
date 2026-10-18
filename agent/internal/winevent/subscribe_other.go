//go:build !windows

package winevent

// Subscribe is only available on Windows.
func Subscribe(channel string, emit func(line string), stop <-chan struct{}) error {
	return ErrUnsupported
}
