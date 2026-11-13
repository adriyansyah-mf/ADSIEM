//go:build !linux

package mountns

// HostPath: mount namespaces are Linux only.
func HostPath(int, string) string { return "" }

// Candidate is an existing file a path from another mount namespace can mean.
type Candidate struct {
	Path    string
	Running bool
}

// Locate: mount namespaces are Linux only.
func Locate(string) []Candidate { return nil }
