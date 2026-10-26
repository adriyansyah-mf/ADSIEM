//go:build !linux

package linsensor

import "errors"

type Options struct {
	Push     func(logType, line string)
	OnFile   func(FileEvent)
	Disabled []string
}

type Sensor struct{}

func Start(Options) (*Sensor, error) { return nil, errors.New("linsensor: Linux only") }

func (*Sensor) Stop() {}
