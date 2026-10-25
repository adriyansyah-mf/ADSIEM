//go:build !windows

package etw

// Session is a running ETW session; off Windows none can start.
type Session struct{}

// Start is only available on Windows.
func Start(Config, func(*Event)) (*Session, error) { return nil, ErrUnsupported }

// Close is a no-op off Windows.
func (*Session) Close() error { return nil }
