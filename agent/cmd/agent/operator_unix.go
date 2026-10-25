//go:build !windows

package main

import (
	"errors"
	"os"
)

// operatorIdentity: the journal belongs to the root service.
func operatorIdentity() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root: the evidence journal belongs to the agent service")
	}
	return nil
}
