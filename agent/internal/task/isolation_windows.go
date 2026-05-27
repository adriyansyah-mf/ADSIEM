//go:build windows

// agent/internal/task/isolation_windows.go
package task

import "fmt"

func isolateHost(_ string) error {
	return fmt.Errorf("network isolation not supported on Windows")
}

func unisolateHost() error {
	return fmt.Errorf("network isolation not supported on Windows")
}
