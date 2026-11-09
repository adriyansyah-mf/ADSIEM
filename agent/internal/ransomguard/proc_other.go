//go:build !linux && !windows

package ransomguard

// No process table and nothing to kill elsewhere (kill_other.go).
func liveProcs() procLookup { return nil }

func procCwd(uint32) string { return "" }

var fileRootOwned func(string) bool

var runSystemCmd func(name string, args ...string) error
