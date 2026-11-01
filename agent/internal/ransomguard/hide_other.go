//go:build !windows

package ransomguard

// Dot-file names are what hides a canary outside Windows.
func prepareWrite(string) {}
func hideFile(string)     {}
