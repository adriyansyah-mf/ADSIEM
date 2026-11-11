//go:build !linux

package credwatch

import "errors"

// Watcher is Linux only: on Windows the ETW sensor (winsensor) reports the
// opens it already sees.
type Watcher struct{}

// Start is Linux only.
func Start(func(logType, line string)) (*Watcher, error) {
	return nil, errors.New("credwatch: the fanotify watch is Linux only")
}

// Stop does nothing.
func (w *Watcher) Stop() {}
