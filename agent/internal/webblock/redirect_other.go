//go:build !linux

package webblock

// defaultPlan binds the sink addresses directly. Windows lets a later
// wildcard bind of the same port succeed (TestWindowsWildcardBindAfterSink),
// so no redirect is needed there.
func (s *Server) defaultPlan() ([]bindSpec, Redirector) {
	return []bindSpec{
		{name: "http4", addr: AddrHTTP4, label: AddrHTTP4},
		{name: "https4", addr: AddrHTTPS4, label: AddrHTTPS4, tls: true},
		{name: "http6", addr: AddrHTTP6, label: AddrHTTP6, v6: true},
		{name: "https6", addr: AddrHTTPS6, label: AddrHTTPS6, tls: true, v6: true},
	}, nil
}

func removeRedirects() error { return nil }
