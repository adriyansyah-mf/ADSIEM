//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// operatorIdentity: the journal belongs to the SYSTEM service; administrators
// must run from an elevated prompt.
func operatorIdentity() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run from an elevated prompt: the evidence journal belongs to the agent service")
	}
	return nil
}
