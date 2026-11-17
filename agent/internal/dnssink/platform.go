package dnssink

import "runtime"

// NewRouter is the OS's router: NRPT on Windows (ps runs PowerShell),
// systemd-resolved on Linux, none elsewhere.
func NewRouter(ps PSRunner) Router {
	switch runtime.GOOS {
	case "windows":
		return NRPTRouter{Run: ps}
	case "linux":
		return ResolvedRouter{}
	}
	return noRouter{}
}

type noRouter struct{}

func (noRouter) Apply(domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	return ErrUnavailable
}
func (noRouter) Remove() error            { return nil }
func (noRouter) Prepare() (string, error) { return "", ErrUnavailable }
