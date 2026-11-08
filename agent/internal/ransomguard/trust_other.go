//go:build !windows

package ransomguard

// verifyMicrosoft is Windows Authenticode; nothing is signed elsewhere.
func verifyMicrosoft(string) bool { return false }
